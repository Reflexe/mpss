// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/security_type.h"
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#ifdef MPSS_BACKEND_NOOP
#include "mpss/impl/noop/noop_backend.h"
#endif

namespace mpss::tests
{

// Scenario: The wire/ABI ordinals of SecurityType are read by the C API, JNI, and OpenSSL callers.
// Expected behavior: the four values are exactly 0, 1, 2, 3, in the agreed order.
TEST(SecurityType, OrdinalsAreStable)
{
    EXPECT_EQ(0U, static_cast<std::uint8_t>(SecurityType::software));
    EXPECT_EQ(1U, static_cast<std::uint8_t>(SecurityType::mixed));
    EXPECT_EQ(2U, static_cast<std::uint8_t>(SecurityType::hardware));
    EXPECT_EQ(3U, static_cast<std::uint8_t>(SecurityType::secure_element));
    EXPECT_EQ(3U, max_security_type_value);
}

// Scenario: Every combination of a key's guaranteed tier and a caller's required floor.
// Expected behavior: a tier satisfies a floor exactly when it is at least as strong.
TEST(SecurityType, MeetsMinimumMatrix)
{
    EXPECT_TRUE(meets_minimum(SecurityType::software, SecurityType::software));
    EXPECT_FALSE(meets_minimum(SecurityType::software, SecurityType::mixed));
    EXPECT_FALSE(meets_minimum(SecurityType::software, SecurityType::hardware));
    EXPECT_FALSE(meets_minimum(SecurityType::software, SecurityType::secure_element));

    EXPECT_TRUE(meets_minimum(SecurityType::mixed, SecurityType::software));
    EXPECT_TRUE(meets_minimum(SecurityType::mixed, SecurityType::mixed));
    EXPECT_FALSE(meets_minimum(SecurityType::mixed, SecurityType::hardware));
    EXPECT_FALSE(meets_minimum(SecurityType::mixed, SecurityType::secure_element));

    EXPECT_TRUE(meets_minimum(SecurityType::hardware, SecurityType::software));
    EXPECT_TRUE(meets_minimum(SecurityType::hardware, SecurityType::mixed));
    EXPECT_TRUE(meets_minimum(SecurityType::hardware, SecurityType::hardware));
    EXPECT_FALSE(meets_minimum(SecurityType::hardware, SecurityType::secure_element));

    EXPECT_TRUE(meets_minimum(SecurityType::secure_element, SecurityType::software));
    EXPECT_TRUE(meets_minimum(SecurityType::secure_element, SecurityType::mixed));
    EXPECT_TRUE(meets_minimum(SecurityType::secure_element, SecurityType::hardware));
    EXPECT_TRUE(meets_minimum(SecurityType::secure_element, SecurityType::secure_element));
}

// Scenario: A raw integer arrives from a C, JNI, or OpenSSL boundary.
// Expected behavior: only the four defined ordinals are accepted; anything above is rejected
// rather than clamped.
TEST(SecurityType, RejectsOutOfRangeValues)
{
    EXPECT_TRUE(is_valid_security_type(0));
    EXPECT_TRUE(is_valid_security_type(1));
    EXPECT_TRUE(is_valid_security_type(2));
    EXPECT_TRUE(is_valid_security_type(3));
    EXPECT_FALSE(is_valid_security_type(4));
    EXPECT_FALSE(is_valid_security_type(255));
}

// Scenario: Availability is asked for the same algorithm at two different floors.
// Expected behavior: the answers are kept apart. A stronger floor can never be available while a
// weaker one is not, which is what a cache keyed only by algorithm would get wrong.
TEST(SecurityType, AvailabilityIsKeyedByFloor)
{
    for (const Algorithm algorithm :
         {Algorithm::ecdsa_secp256r1_sha256, Algorithm::ecdsa_secp384r1_sha384, Algorithm::ecdsa_secp521r1_sha512})
    {
        const bool at_secure_element = is_algorithm_available(algorithm, SecurityType::secure_element);
        const bool at_software = is_algorithm_available(algorithm, SecurityType::software);
        EXPECT_TRUE(!at_secure_element || at_software)
            << "An algorithm available at the strongest floor must also be available with no floor.";

        // Repeat, so a cached answer for one floor cannot leak into the other.
        EXPECT_EQ(at_software, is_algorithm_available(algorithm, SecurityType::software));
        EXPECT_EQ(at_secure_element, is_algorithm_available(algorithm, SecurityType::secure_element));
    }
}

#ifdef MPSS_BACKEND_NOOP

// The noop backend reports whatever tier it is told to and never enforces a floor itself, so these
// tests observe the enforcement the registry applies on top of any backend.
class SecurityTypeFloor : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        impl::noop::reset();
    }

    void TearDown() override
    {
        impl::noop::reset();
    }

    static constexpr const char *backend = "noop";
    static constexpr Algorithm algorithm = Algorithm::ecdsa_secp256r1_sha256;
};

// Scenario: A backend reports a tier that satisfies the requested floor.
// Expected behavior: the key is returned and reports the tier the backend gave it.
TEST_F(SecurityTypeFloor, CreateAtOrAboveFloorSucceeds)
{
    impl::noop::set_settings({SecurityType::hardware, /* fail_delete */ false});

    const std::unique_ptr<KeyPair> key =
        KeyPair::Create("floor_ok_key", algorithm, backend, KeyPolicy::none, SecurityType::mixed);
    ASSERT_NE(nullptr, key);
    EXPECT_EQ(SecurityType::hardware, key->key_info().security_type);
    EXPECT_TRUE(key->delete_key());
}

// Scenario: The default floor is used, so no minimum is requested at all.
// Expected behavior: a software key is accepted, because software is ordinal zero and every valid
// tier satisfies it.
TEST_F(SecurityTypeFloor, DefaultFloorAcceptsSoftware)
{
    impl::noop::set_settings({SecurityType::software, /* fail_delete */ false});

    const std::unique_ptr<KeyPair> key = KeyPair::Create("floor_default_key", algorithm, backend);
    ASSERT_NE(nullptr, key);
    EXPECT_EQ(SecurityType::software, key->key_info().security_type);
    EXPECT_TRUE(key->delete_key());
}

// Scenario: A key is created but its guaranteed tier turns out to be below the requested floor.
// Expected behavior: creation fails, the rejected key is never returned, and it is deleted rather
// than left behind for a later open to find.
TEST_F(SecurityTypeFloor, BelowFloorCreateDeletesTheKey)
{
    impl::noop::set_settings({SecurityType::software, /* fail_delete */ false});

    const std::unique_ptr<KeyPair> key =
        KeyPair::Create("floor_reject_key", algorithm, backend, KeyPolicy::none, SecurityType::hardware);
    EXPECT_EQ(nullptr, key);

    const std::string error = get_error();
    EXPECT_NE(std::string::npos, error.find("software"));
    EXPECT_NE(std::string::npos, error.find("hardware"));

    // The key must be gone, not merely withheld.
    EXPECT_EQ(nullptr, KeyPair::Open("floor_reject_key", backend));
}

// Scenario: A key is rejected for being below the floor and deleting it also fails.
// Expected behavior: creation still fails and never returns the key, and the error says manual
// cleanup may be required instead of silently hiding the orphan.
TEST_F(SecurityTypeFloor, CleanupFailureIsReported)
{
    impl::noop::set_settings({SecurityType::software, /* fail_delete */ true});

    const std::unique_ptr<KeyPair> key =
        KeyPair::Create("floor_orphan_key", algorithm, backend, KeyPolicy::none, SecurityType::secure_element);
    EXPECT_EQ(nullptr, key);
    EXPECT_NE(std::string::npos, get_error().find("Manual cleanup"));

    // The orphan really is still there; clean it up so the test leaves no state behind.
    impl::noop::set_settings({SecurityType::software, /* fail_delete */ false});
    const std::unique_ptr<KeyPair> orphan = KeyPair::Open("floor_orphan_key", backend);
    ASSERT_NE(nullptr, orphan);
    EXPECT_TRUE(orphan->delete_key());
}

// Scenario: An existing key is opened with a floor it no longer meets, because reopening
// reclassifies it rather than trusting what creation reported.
// Expected behavior: the open fails and the key is released, but the stored key is left intact --
// opening must never delete.
TEST_F(SecurityTypeFloor, BelowFloorOpenReleasesWithoutDeleting)
{
    impl::noop::set_settings({SecurityType::hardware, /* fail_delete */ false});
    const std::unique_ptr<KeyPair> created =
        KeyPair::Create("floor_open_key", algorithm, backend, KeyPolicy::none, SecurityType::hardware);
    ASSERT_NE(nullptr, created);

    // The same key now classifies lower than it did at creation.
    impl::noop::set_settings({SecurityType::software, /* fail_delete */ false});
    EXPECT_EQ(nullptr, KeyPair::Open("floor_open_key", backend, SecurityType::hardware));

    // Rejecting the open must not have destroyed it.
    const std::unique_ptr<KeyPair> reopened = KeyPair::Open("floor_open_key", backend);
    ASSERT_NE(nullptr, reopened);
    EXPECT_EQ(SecurityType::software, reopened->key_info().security_type);
    EXPECT_TRUE(reopened->delete_key());
}

// Scenario: Availability is probed at a floor the backend's keys cannot reach.
// Expected behavior: the algorithm is reported unavailable at that floor and available below it,
// and the probe key is not left behind.
TEST_F(SecurityTypeFloor, AvailabilityHonorsTheFloor)
{
    impl::noop::set_settings({SecurityType::mixed, /* fail_delete */ false});

    EXPECT_TRUE(is_algorithm_available(algorithm, backend, SecurityType::software));
    EXPECT_TRUE(is_algorithm_available(algorithm, backend, SecurityType::mixed));
    EXPECT_FALSE(is_algorithm_available(algorithm, backend, SecurityType::hardware));
    EXPECT_FALSE(is_algorithm_available(algorithm, backend, SecurityType::secure_element));
}

#endif // MPSS_BACKEND_NOOP

#ifdef _WIN32

// These run on any Windows host, with or without a TPM, because floor pruning happens before a
// provider is ever opened. They are the only Windows coverage that executes on a CI runner, where
// no TPM exists and every key-creating test skips.

// Scenario: Windows is asked for a guarantee no Windows mechanism can provide.
// Expected behavior: the request fails, names the tier that could not be met, and persists nothing.
TEST(SecurityTypeWindows, SecureElementFloorIsRejectedWithoutCreatingAKey)
{
    const std::string key_name = "win_floor_reject_key";

    const std::unique_ptr<KeyPair> key = KeyPair::Create(key_name, Algorithm::ecdsa_secp256r1_sha256, "os",
                                                         KeyPolicy::none, SecurityType::secure_element);
    EXPECT_EQ(nullptr, key);
    EXPECT_NE(std::string::npos, get_error().find("secure_element"));

    // Pruning happens before creation, so there must be nothing left behind to find.
    EXPECT_EQ(nullptr, KeyPair::Open(key_name, "os"));
}

// Scenario: an existing key is opened with a floor Windows cannot reach.
// Expected behavior: the open fails rather than reporting an inflated tier.
TEST(SecurityTypeWindows, SecureElementFloorIsRejectedOnOpen)
{
    EXPECT_EQ(nullptr, KeyPair::Open("win_floor_open_key", "os", SecurityType::secure_element));
}

// Scenario: availability is asked at a floor above what Windows provides.
// Expected behavior: unavailable, and no probe key is created to find that out.
TEST(SecurityTypeWindows, SecureElementFloorIsUnavailable)
{
    EXPECT_FALSE(is_algorithm_available(Algorithm::ecdsa_secp256r1_sha256, "os", SecurityType::secure_element));
    EXPECT_FALSE(is_algorithm_available(Algorithm::ecdsa_secp384r1_sha384, "os", SecurityType::secure_element));
    EXPECT_FALSE(is_algorithm_available(Algorithm::ecdsa_secp521r1_sha512, "os", SecurityType::secure_element));
}

// Scenario: a key is actually created on a host that has a usable TPM.
// Expected behavior: it reports the hardware tier and the TPM storage description, and it
// satisfies every floor up to and including hardware.
TEST(SecurityTypeWindows, CreatedKeyReportsHardware)
{
    constexpr Algorithm algorithm = Algorithm::ecdsa_secp256r1_sha256;
    if (!is_algorithm_available(algorithm, "os"))
    {
        GTEST_SKIP() << "No usable TPM on this host";
    }

    const std::string key_name = "win_tier_key";
    const std::unique_ptr<KeyPair> key =
        KeyPair::Create(key_name, algorithm, "os", KeyPolicy::none, SecurityType::hardware);
    ASSERT_NE(nullptr, key);
    EXPECT_EQ(SecurityType::hardware, key->key_info().security_type);
    EXPECT_EQ(std::string{"TPM Protection"}, std::string{key->key_info().storage_description});

    // Reopening reclassifies the key rather than replaying what creation reported.
    const std::unique_ptr<KeyPair> reopened = KeyPair::Open(key_name, "os", SecurityType::hardware);
    ASSERT_NE(nullptr, reopened);
    EXPECT_EQ(SecurityType::hardware, reopened->key_info().security_type);

    EXPECT_TRUE(key->delete_key());
}

// Scenario: a key is deleted, whose Windows implementation frees the underlying handle as part of
// deleting it.
// Expected behavior: the key pair does not close that handle a second time, and destroying it
// afterwards is safe.
TEST(SecurityTypeWindows, DeleteThenDestroyDoesNotDoubleFree)
{
    constexpr Algorithm algorithm = Algorithm::ecdsa_secp256r1_sha256;
    if (!is_algorithm_available(algorithm, "os"))
    {
        GTEST_SKIP() << "No usable TPM on this host";
    }

    std::unique_ptr<KeyPair> key = KeyPair::Create("win_double_free_key", algorithm, "os");
    ASSERT_NE(nullptr, key);
    EXPECT_TRUE(key->delete_key());

    // Destroying the pair after a successful delete must not touch the freed handle again.
    key.reset();
}

#endif // _WIN32

} // namespace mpss::tests
