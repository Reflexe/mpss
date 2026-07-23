// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include "mpss/mpss.h"
#include "tests/mock_pki/mock_pki.h"
#include "tests/mock_pki/test_ca.h"
#include <chrono>
#include <cstddef>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace mpss::tests
{

namespace
{

using mpss::tests::mock_pki::MockCsr;
using mpss::tests::mock_pki::MockPkiService;
using mpss::tests::mock_pki::RejectReason;

// Overrides only the pure-virtual methods, leaving the attestation accessors at their base
// defaults, so the no-evidence contract is testable without a hardware backend.
class NoEvidenceKeyPair : public mpss::KeyPair
{
  public:
    NoEvidenceKeyPair() : mpss::KeyPair(mpss::Algorithm::ecdsa_secp256r1_sha256, /* hardware_backed */ true, "test")
    {
    }

    bool delete_key() override
    {
        return true;
    }

    std::size_t sign_hash(std::span<const std::byte> /*hash*/, std::span<std::byte> /*sig*/) const override
    {
        return 0;
    }

    bool verify(std::span<const std::byte> /*hash*/, std::span<const std::byte> /*sig*/) const override
    {
        return false;
    }

    std::size_t extract_key(std::span<std::byte> /*public_key*/) const override
    {
        return 0;
    }

    void release_key() override
    {
    }
};

std::vector<std::byte> make_bytes(std::size_t count, std::byte value)
{
    return std::vector<std::byte>(count, value);
}

} // namespace

// --- Capability reporting ---

// Scenario: querying the OS backend's attestation capability on each platform.
// Expected behavior: Windows/Android/Apple all report key_attestation (they attest the key),
// and platforms without a registered OS backend report none.
TEST(AttestationCapabilityTest, OsBackendReportsExpectedCapability)
{
    const mpss::AttestationCapability cap = mpss::KeyPair::attestation_capability("os");
#if defined(_WIN32)
    EXPECT_EQ(cap, mpss::AttestationCapability::key_attestation);
#elif defined(__APPLE__)
    EXPECT_EQ(cap, mpss::AttestationCapability::key_attestation);
#elif defined(__ANDROID__)
    EXPECT_EQ(cap, mpss::AttestationCapability::key_attestation);
#else
    EXPECT_EQ(cap, mpss::AttestationCapability::none);
#endif
}

// Scenario: querying capability for a backend name that is not registered.
// Expected behavior: the query reports none rather than failing.
TEST(AttestationCapabilityTest, UnknownBackendReportsNone)
{
    EXPECT_EQ(mpss::KeyPair::attestation_capability("this-backend-does-not-exist"),
              mpss::AttestationCapability::none);
}

// Scenario: the capability query defaults its backend argument to "os".
// Expected behavior: the default-argument overload matches the explicit "os" query.
TEST(AttestationCapabilityTest, DefaultsToOsBackend)
{
    EXPECT_EQ(mpss::KeyPair::attestation_capability(), mpss::KeyPair::attestation_capability("os"));
}

// --- Attestation request validation ---

// Scenario: requesting attestation with an empty challenge via the default-backend overload.
// Expected behavior: creation is rejected (nullptr) before any backend work happens.
TEST(AttestationApiTest, EmptyChallengeRejectedDefaultBackend)
{
    mpss::AttestationRequest request; // challenge is empty
    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(
        "mpss_att_empty_default", mpss::Algorithm::ecdsa_secp256r1_sha256, mpss::KeyPolicy::none, std::move(request));
    EXPECT_EQ(nullptr, key);
}

// Scenario: requesting attestation with an empty challenge via the explicit-backend overload.
// Expected behavior: creation is rejected (nullptr) regardless of the named backend.
TEST(AttestationApiTest, EmptyChallengeRejectedExplicitBackend)
{
    mpss::AttestationRequest request; // challenge is empty
    std::unique_ptr<mpss::KeyPair> key =
        mpss::KeyPair::Create("mpss_att_empty_explicit", mpss::Algorithm::ecdsa_secp256r1_sha256, "os",
                              mpss::KeyPolicy::none, std::move(request));
    EXPECT_EQ(nullptr, key);
}

// --- supports_attestation() / attestation() semantics ---

// Scenario: a key pair whose backend produces no evidence (the Stage 1 state for all backends).
// Expected behavior: supports_attestation() is false and attestation() is nullopt.
TEST(AttestationApiTest, KeyPairDefaultsToNoEvidence)
{
    NoEvidenceKeyPair key;
    EXPECT_FALSE(key.supports_attestation());
    EXPECT_FALSE(key.attestation().has_value());
}

// --- Shared verifier skeleton ---

// Scenario: verifying evidence whose format is none.
// Expected behavior: the verifier rejects it with a non-empty reason and echoes the none format.
TEST(AttestationVerifierTest, NoneEvidenceIsRejected)
{
    const mpss::attest::AttestationVerifier verifier;
    const mpss::AttestationEvidence evidence; // format defaults to none
    const std::vector<std::byte> nonce = make_bytes(8, std::byte{0x11});
    const std::vector<std::byte> pubkey = make_bytes(8, std::byte{0x22});

    const mpss::attest::AttestationVerifier::Result result = verifier.verify(evidence, nonce, pubkey);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, mpss::AttestationFormat::none);
    EXPECT_FALSE(result.reason.empty());
}

// Scenario: verifying evidence for each real format against the Stage 1 skeleton.
// Expected behavior: every per-format verifier reports "not implemented" and echoes the format.
TEST(AttestationVerifierTest, EachFormatReportsNotImplemented)
{
    const mpss::attest::AttestationVerifier verifier;
    const std::vector<std::byte> nonce = make_bytes(8, std::byte{0x11});
    const std::vector<std::byte> pubkey = make_bytes(8, std::byte{0x22});

    for (const mpss::AttestationFormat format :
         {mpss::AttestationFormat::android_key_attestation, mpss::AttestationFormat::apple_acme_managed_device,
          mpss::AttestationFormat::windows_tpm_claim, mpss::AttestationFormat::windows_vbs_claim})
    {
        mpss::AttestationEvidence evidence;
        evidence.format = format;

        const mpss::attest::AttestationVerifier::Result result = verifier.verify(evidence, nonce, pubkey);
        EXPECT_FALSE(result.ok);
        EXPECT_EQ(result.format, format); // the format is echoed so callers can distinguish real vs VBS
        EXPECT_NE(result.reason.find("not implemented"), std::string::npos);
    }
}

// --- Reduced mock PKI: nonce bookkeeping + a call into the shared verifier ---

// Scenario: submitting a CSR with no attestation evidence.
// Expected behavior: rejected as missing_evidence, before any nonce or verifier work.
TEST(MockPkiTest, MissingEvidenceRejected)
{
    MockPkiService pki;
    const std::vector<std::byte> nonce = pki.issue_challenge();
    const MockCsr csr{make_bytes(8, std::byte{0x05})};

    const auto result = pki.submit(csr, std::nullopt, nonce, mpss::AttestationFormat::android_key_attestation);
    EXPECT_FALSE(result.signed_cert);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(*result.reject_reason, RejectReason::missing_evidence);
}

// Scenario: submitting evidence whose format differs from the one the PKI expects.
// Expected behavior: rejected as wrong_format.
TEST(MockPkiTest, WrongFormatRejected)
{
    MockPkiService pki;
    const std::vector<std::byte> nonce = pki.issue_challenge();
    const MockCsr csr{make_bytes(8, std::byte{0x05})};

    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;

    const auto result = pki.submit(csr, evidence, nonce, mpss::AttestationFormat::android_key_attestation);
    EXPECT_FALSE(result.signed_cert);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(*result.reject_reason, RejectReason::wrong_format);
}

// Scenario: submitting evidence bound to a nonce the PKI never issued.
// Expected behavior: rejected as nonce_not_found.
TEST(MockPkiTest, UnknownNonceRejected)
{
    MockPkiService pki;
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x7E}); // never issued
    const MockCsr csr{make_bytes(8, std::byte{0x05})};

    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::android_key_attestation;

    const auto result = pki.submit(csr, evidence, nonce, mpss::AttestationFormat::android_key_attestation);
    EXPECT_FALSE(result.signed_cert);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(*result.reject_reason, RejectReason::nonce_not_found);
}

// Scenario: presenting the same issued nonce twice.
// Expected behavior: the first presentation spends the nonce; the second is nonce_replayed.
TEST(MockPkiTest, ReplayedNonceRejected)
{
    MockPkiService pki;
    const std::vector<std::byte> nonce = pki.issue_challenge();
    const MockCsr csr{make_bytes(8, std::byte{0x05})};

    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::android_key_attestation;

    const auto first = pki.submit(csr, evidence, nonce, mpss::AttestationFormat::android_key_attestation);
    // First presentation passes bookkeeping and reaches the (not-yet-implemented) verifier.
    ASSERT_TRUE(first.reject_reason.has_value());
    EXPECT_EQ(*first.reject_reason, RejectReason::verifier_rejected);

    const auto second = pki.submit(csr, evidence, nonce, mpss::AttestationFormat::android_key_attestation);
    ASSERT_TRUE(second.reject_reason.has_value());
    EXPECT_EQ(*second.reject_reason, RejectReason::nonce_replayed);
}

// Scenario: presenting a nonce after its TTL has elapsed (deterministic injected clock).
// Expected behavior: rejected as nonce_expired.
TEST(MockPkiTest, ExpiredNonceRejected)
{
    auto clock_now = std::chrono::steady_clock::now();
    MockPkiService pki{std::chrono::seconds{1}};
    pki.set_clock([&clock_now] { return clock_now; });

    const std::vector<std::byte> nonce = pki.issue_challenge(); // expires at clock_now + 1s
    clock_now += std::chrono::seconds{5};                       // advance past expiry

    const MockCsr csr{make_bytes(8, std::byte{0x05})};
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::android_key_attestation;

    const auto result = pki.submit(csr, evidence, nonce, mpss::AttestationFormat::android_key_attestation);
    EXPECT_FALSE(result.signed_cert);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(*result.reject_reason, RejectReason::nonce_expired);
}

// Scenario: a fresh nonce and a real (test-CA) certificate chain flow all the way to the verifier.
// Expected behavior: bookkeeping passes, the shared verifier is consulted, and it reports the
// format back with "not implemented" (Stage 1), so the CSR is not signed.
TEST(MockPkiTest, FreshEvidenceReachesVerifier)
{
    using mpss::tests::mock_pki::create_leaf;
    using mpss::tests::mock_pki::create_root;
    using mpss::tests::mock_pki::generate_ec_key;

    const mpss::tests::mock_pki::TestKey root_key = generate_ec_key();
    const mpss::tests::mock_pki::TestKey leaf_key = generate_ec_key();
    ASSERT_TRUE(root_key.valid());
    ASSERT_TRUE(leaf_key.valid());

    const mpss::tests::mock_pki::TestCert root = create_root(root_key, "MPSS Stage 1 Test Root");
    const mpss::tests::mock_pki::TestCert leaf = create_leaf(leaf_key, root_key, root, "MPSS Stage 1 Test Leaf");
    ASSERT_TRUE(root.valid());
    ASSERT_TRUE(leaf.valid());

    MockPkiService pki;
    pki.set_trusted_root(mpss::AttestationFormat::android_key_attestation, mpss::attest::TrustAnchor{root.der});
    const std::vector<std::byte> nonce = pki.issue_challenge();

    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::android_key_attestation;
    evidence.payload = mpss::CertChain{leaf.der, root.der};
    ASSERT_TRUE(std::holds_alternative<mpss::CertChain>(evidence.payload));
    EXPECT_EQ(std::get<mpss::CertChain>(evidence.payload).size(), 2U);

    const MockCsr csr{leaf_key.spki_der};
    const auto result = pki.submit(csr, evidence, nonce, mpss::AttestationFormat::android_key_attestation);

    EXPECT_FALSE(result.signed_cert);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(*result.reject_reason, RejectReason::verifier_rejected);
    EXPECT_EQ(result.verifier_result.format, mpss::AttestationFormat::android_key_attestation);
    EXPECT_FALSE(result.verifier_result.ok);
}

// --- Central AttestationRequirement::require enforcement ---
//
// The fail-closed net lives in KeyPair::Create behind the backend registry, so exercising it
// needs a real backend that creates a key (Stage 1 backends never attest). These follow the
// repo convention of gating backend-dependent tests on is_algorithm_available and are kept out
// of the backend-free sanitizer filter.

// Scenario: attestation is required but the backend produces no evidence (the Stage 1 state).
// Expected behavior: Create returns nullptr and leaves no key behind in storage.
TEST(AttestationRequireTest, RequireWithoutEvidenceFailsClosed)
{
    if (!mpss::is_algorithm_available(mpss::Algorithm::ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "No backend can create the test key on this runner";
    }

    const std::string key_name = "mpss_att_require_no_evidence";
    if (auto existing = mpss::KeyPair::Open(key_name))
    {
        ASSERT_TRUE(existing->delete_key());
    }

    mpss::AttestationRequest request;
    request.challenge = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    request.requirement = mpss::AttestationRequirement::require;

    auto key = mpss::KeyPair::Create(key_name, mpss::Algorithm::ecdsa_secp256r1_sha256, mpss::KeyPolicy::none,
                                     std::move(request));

    EXPECT_EQ(nullptr, key);
    EXPECT_EQ(nullptr, mpss::KeyPair::Open(key_name));
}

// Scenario: attestation is only requested (best-effort) on a backend that produces no evidence.
// Expected behavior: the key is created and reports supports_attestation() == false.
TEST(AttestationRequireTest, RequestWithoutEvidenceKeepsKey)
{
    if (!mpss::is_algorithm_available(mpss::Algorithm::ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "No backend can create the test key on this runner";
    }

    const std::string key_name = "mpss_att_request_no_evidence";
    if (auto existing = mpss::KeyPair::Open(key_name))
    {
        ASSERT_TRUE(existing->delete_key());
    }

    mpss::AttestationRequest request;
    request.challenge = {std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C}, std::byte{0x0D}};
    request.requirement = mpss::AttestationRequirement::request;

    auto key = mpss::KeyPair::Create(key_name, mpss::Algorithm::ecdsa_secp256r1_sha256, mpss::KeyPolicy::none,
                                     std::move(request));

    ASSERT_NE(nullptr, key);
    EXPECT_FALSE(key->supports_attestation());
    EXPECT_TRUE(key->delete_key());
}

// Scenario #3 (require + a backend that DOES attest -> key returned) is not covered here: no
// Stage 1 backend produces evidence, and injecting a fake attesting backend would need the
// non-exported registry API, breaking the shared-library build. It lands with the first real
// attesting backend in a later stage.

} // namespace mpss::tests
