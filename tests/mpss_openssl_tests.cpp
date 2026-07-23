// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss/key_policy.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/core.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <random>
#include <vector>

#ifndef MPSS_OPENSSL_IS_SHARED
// White-box access to the provider's one-shot digest dispatch (OSSL_FUNC_DIGEST_DIGEST). This entry
// point is provider-internal, so it is only linkable when mpss_openssl is built statically.
extern "C" int mpss_digest_digest_SHA256(void *provctx, const unsigned char *in, std::size_t inl, unsigned char *out,
                                         std::size_t *outl, std::size_t outsz);
#endif

namespace
{

class MPSSDigest : public ::testing::Test
{
  protected:
    OSSL_LIB_CTX *mpss_libctx = nullptr;
    OSSL_PROVIDER *mpss_prov = nullptr;
    OSSL_PROVIDER *default_prov = nullptr;

    void SetUp() override
    {
        mpss_libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, mpss_libctx);

        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
        mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);
        default_prov = OSSL_PROVIDER_load(mpss_libctx, "default");
        ASSERT_NE(nullptr, default_prov);
    }

    void TearDown() override
    {
        if (nullptr != mpss_prov)
        {
            ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
            mpss_prov = nullptr;
        }
        if (nullptr != default_prov)
        {
            ASSERT_NE(0, OSSL_PROVIDER_unload(default_prov));
            default_prov = nullptr;
        }
        if (nullptr != mpss_libctx)
        {
            OSSL_LIB_CTX_free(mpss_libctx);
            mpss_libctx = nullptr;
        }
    }

    void TestDigest(const char *hash_name, const EVP_MD *(*evp_md_func)(), std::string_view in)
    {
        unsigned char mpss_digest[EVP_MAX_MD_SIZE];
        unsigned char default_digest[EVP_MAX_MD_SIZE];
        unsigned int mpss_digest_len = 0;
        unsigned int default_digest_len = 0;

        EVP_MD *md = EVP_MD_fetch(mpss_libctx, hash_name, "provider=mpss");
        ASSERT_NE(nullptr, md);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, mdctx);
        ASSERT_EQ(1, EVP_DigestInit(mdctx, md));
        ASSERT_EQ(1, EVP_DigestUpdate(mdctx, in.data(), in.size()));
        unsigned int digest_len = 0;
        ASSERT_EQ(1, EVP_DigestFinal(mdctx, mpss_digest, &digest_len));
        mpss_digest_len = digest_len;
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);

        const EVP_MD *default_md = evp_md_func();
        ASSERT_NE(nullptr, default_md);
        mdctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, mdctx);
        ASSERT_EQ(1, EVP_DigestInit(mdctx, default_md));
        ASSERT_EQ(1, EVP_DigestUpdate(mdctx, in.data(), in.size()));
        ASSERT_EQ(1, EVP_DigestFinal(mdctx, default_digest, &default_digest_len));
        EVP_MD_CTX_free(mdctx);

        ASSERT_EQ(mpss_digest_len, default_digest_len);
        ASSERT_TRUE(
            std::equal(mpss_digest, mpss_digest + mpss_digest_len, default_digest)); // NOLINT(modernize-use-ranges)
    }
};

} // namespace

namespace mpss_openssl::tests
{

TEST_F(MPSSDigest, SHA256)
{
    std::random_device rd;
    for (int i = 0; i < 50; i++)
    {
        const std::size_t size = rd() % (1024 * 1024);
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });
        TestDigest("SHA256", EVP_sha256, input_data);
    }
}

TEST_F(MPSSDigest, SHA384)
{
    std::random_device rd;
    for (int i = 0; i < 50; i++)
    {
        const std::size_t size = rd() % (1024 * 1024);
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });
        TestDigest("SHA384", EVP_sha384, input_data);
    }
}

TEST_F(MPSSDigest, SHA512)
{
    std::random_device rd;
    for (int i = 0; i < 50; i++)
    {
        const std::size_t size = rd() % (1024 * 1024);
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });
        TestDigest("SHA512", EVP_sha512, input_data);
    }
}

TEST_F(MPSSDigest, OneShotDigest)
{
#ifdef MPSS_OPENSSL_IS_SHARED
    GTEST_SKIP() << "Provider-internal one-shot digest entry point is not exported by shared mpss_openssl builds.";
#else
    // Drive the provider's one-shot digest dispatch directly (see the forward declaration above for
    // why the public EVP API can't reach it). This is the entry point that previously leaked a
    // context (+ EVP_MD + EVP_MD_CTX) on every call; looping it here exercises the newctx ->
    // internal -> freectx path and confirms the added free leaves the returned digest correct across
    // repeated invocations. The provider ctx only needs a libctx (what newctx reads).
    mpss_openssl::provider::mpss_provider_ctx pctx{};
    pctx.libctx = mpss_libctx;

    // Known-answer test: SHA-256("abc").
    const std::string_view abc = "abc";
    const unsigned char sha256_abc[] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

    std::random_device rd;
    for (int i = 0; i < 100; i++)
    {
        unsigned char mpss_digest[EVP_MAX_MD_SIZE];
        std::size_t mpss_digest_len = 0;
        ASSERT_EQ(1, mpss_digest_digest_SHA256(&pctx, reinterpret_cast<const unsigned char *>(abc.data()), abc.size(),
                                               mpss_digest, &mpss_digest_len, sizeof(mpss_digest)));
        ASSERT_EQ(sizeof(sha256_abc), mpss_digest_len);
        ASSERT_TRUE(std::equal(mpss_digest, mpss_digest + mpss_digest_len, sha256_abc)); // NOLINT(modernize-use-ranges)

        // Compare the one-shot against the default provider on random input.
        const std::size_t size = rd() % 4096;
        std::string input_data(size, '\0');
        std::ranges::generate(input_data, [&rd]() { return static_cast<char>(rd() % 256); });

        ASSERT_EQ(1, mpss_digest_digest_SHA256(&pctx, reinterpret_cast<const unsigned char *>(input_data.data()),
                                               input_data.size(), mpss_digest, &mpss_digest_len, sizeof(mpss_digest)));

        unsigned char default_digest[EVP_MAX_MD_SIZE];
        std::size_t default_digest_len = 0;
        ASSERT_EQ(1, EVP_Q_digest(mpss_libctx, "SHA256", "provider=default", input_data.data(), input_data.size(),
                                  default_digest, &default_digest_len));
        ASSERT_EQ(mpss_digest_len, default_digest_len);
        ASSERT_TRUE(std::equal(
            mpss_digest, mpss_digest + mpss_digest_len, default_digest)); // NOLINT(modernize-use-ranges)
    }
#endif
}

TEST(MPSS_OpenSSL, GetKeyDescriptors)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *key_name = "test_key_params";
    const bool _ = mpss_delete_key(key_name);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),

        // There is a lot of flexibility in the algorithm name we pass here. For example,
        // this works just fine.
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa with p256 and sha256"), 0),
        OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);

    // Query gettable parameters
    OSSL_PARAM get_params[4];
    int is_hw = -1;
    char storage_desc[256] = {0};
    get_params[0] = OSSL_PARAM_construct_int("is_hardware_backed", &is_hw);
    get_params[1] = OSSL_PARAM_construct_utf8_string("storage_description", storage_desc, sizeof(storage_desc));
    get_params[2] = OSSL_PARAM_END;

    ASSERT_EQ(1, EVP_PKEY_get_params(pkey, get_params));
    // is_hardware_backed should be 0 or 1
    ASSERT_TRUE(0 == is_hw || 1 == is_hw);
    // storage_description should not be empty
    ASSERT_GT(strlen(storage_desc), 0);

    EVP_PKEY_free(pkey);
    ASSERT_EQ(1, mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, GenSetParamsRejectsNullString)
{
    // A keygen string param whose data pointer is NULL must be rejected cleanly:
    // OSSL_PARAM_get_utf8_string_ptr reports success with a nullptr value for such a param. No key is
    // generated here (set_params runs before generate), so this is backend-independent (never skipped).
    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));

    // data pointer NULL, type OSSL_PARAM_UTF8_STRING -> get_utf8_string_ptr yields (1, nullptr).
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("mpss_key_name", nullptr, 0), OSSL_PARAM_END};
    ASSERT_EQ(0, EVP_PKEY_CTX_set_params(ctx, params));

    EVP_PKEY_CTX_free(ctx);
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, DefaultBackendReturned)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *key_name = "test_key_default_backend";
    const bool _ = mpss_delete_key(key_name);

    const char *default_backend = mpss_get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(strlen(default_backend), 0);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    // Create a key without specifying mpss_backend.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);

    // Query mpss_backend - should return the default backend even though we didn't set it.
    char backend_buf[256] = {0};
    OSSL_PARAM get_params[] = {OSSL_PARAM_construct_utf8_string("mpss_backend", backend_buf, sizeof(backend_buf)),
                               OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_get_params(pkey, get_params));
    ASSERT_STREQ(default_backend, backend_buf);

    EVP_PKEY_free(pkey);
    ASSERT_EQ(1, mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, ExplicitBackend)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *key_name = "test_key_explicit_backend";
    const bool _ = mpss_delete_key(key_name);

    const char *default_backend = mpss_get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(strlen(default_backend), 0);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    // Create a key with an explicit backend.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(default_backend), 0), OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);

    // Query the backend via gettable params.
    char backend_buf[256] = {0};
    OSSL_PARAM get_params[] = {OSSL_PARAM_construct_utf8_string("mpss_backend", backend_buf, sizeof(backend_buf)),
                               OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_get_params(pkey, get_params));
    ASSERT_STREQ(default_backend, backend_buf);

    EVP_PKEY_free(pkey);
    ASSERT_EQ(1, mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

TEST(MPSS_OpenSSL, DeleteKeyFromBackend)
{
    const char **backends = mpss_get_available_backends();
    ASSERT_NE(nullptr, backends);
    if (nullptr == backends[0])
    {
        GTEST_SKIP() << "No backends available.";
    }

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    int backends_tested = 0;
    for (const char **b = backends; nullptr != *b; ++b)
    {
        const char *backend = *b;

        if (!mpss_is_algorithm_available_in_backend("ecdsa_secp256r1_sha256", backend))
        {
            continue;
        }

        const std::string key_name = std::string("test_delete_from_backend_") + backend;

        // Clean up a possible leftover from a previous run.
        mpss_delete_key_from_backend(key_name.c_str(), backend);

        // Create a key in this specific backend. The backend may be registered
        // without an underlying device being currently available (e.g., no
        // YubiKey plugged in), so treat key generation failure as "backend not
        // currently usable" and continue to the next one.
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
            OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(backend), 0), OSSL_PARAM_END};
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
        EVP_PKEY *pkey = nullptr;
        if (1 != EVP_PKEY_generate(ctx, &pkey))
        {
            EVP_PKEY_CTX_free(ctx);
            continue;
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        // Delete the key from this specific backend.
        ASSERT_TRUE(mpss_delete_key_from_backend(key_name.c_str(), backend));

        // Attempting to delete again should fail (key no longer exists).
        ASSERT_FALSE(mpss_delete_key_from_backend(key_name.c_str(), backend));

        ++backends_tested;
    }

    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);

    if (0 == backends_tested)
    {
        GTEST_SKIP() << "No backends support ecdsa_secp256r1_sha256.";
    }
}

// --- KeyPolicy C define / C++ enum agreement tests ---

TEST(KeyPolicyDefines, NoneMatchesCppEnum)
{
    static_assert(MPSS_KEY_POLICY_NONE == static_cast<std::uint64_t>(mpss::KeyPolicy::none));
}

#ifdef MPSS_BACKEND_YUBIKEY

TEST(KeyPolicyDefines, YubikeyPinDefinesMatchCppEnum)
{
    static_assert(MPSS_KEY_POLICY_YUBIKEY_PIN_NEVER == static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_never));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE == static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_once));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_PIN_ALWAYS ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_pin_always));
}

TEST(KeyPolicyDefines, YubikeyTouchDefinesMatchCppEnum)
{
    static_assert(MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_never));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_TOUCH_ALWAYS ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_always));
    static_assert(MPSS_KEY_POLICY_YUBIKEY_TOUCH_CACHED ==
                  static_cast<std::uint64_t>(mpss::KeyPolicy::yubikey_touch_cached));
}

#endif // MPSS_BACKEND_YUBIKEY

// --- KeyPolicy provider parameter pass-through test ---

TEST(MPSS_OpenSSL, CreateKeyWithPolicyParam)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *key_name = "test_key_policy_provider";
    const bool _ = mpss_delete_key(key_name);

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));

    // Pass mpss_key_policy = MPSS_KEY_POLICY_NONE through the provider parameter.
    std::uint64_t policy = MPSS_KEY_POLICY_NONE;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_construct_uint64("mpss_key_policy", &policy), OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    ASSERT_NE(nullptr, pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    ASSERT_TRUE(mpss_delete_key(key_name));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

// Fixture for the OSSL_STORE "open existing key by name" flow. Loads the mpss provider (key
// management / signing) and the default provider (to verify signatures against an extracted public
// key) into a private library context.
class MPSSStore : public ::testing::Test
{
  protected:
    OSSL_LIB_CTX *libctx = nullptr;
    OSSL_PROVIDER *mpss_prov = nullptr;
    OSSL_PROVIDER *default_prov = nullptr;

    void SetUp() override
    {
        libctx = OSSL_LIB_CTX_new();
        ASSERT_NE(nullptr, libctx);
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(libctx, "mpss", OSSL_provider_init));
        mpss_prov = OSSL_PROVIDER_load(libctx, "mpss");
        ASSERT_NE(nullptr, mpss_prov);
        default_prov = OSSL_PROVIDER_load(libctx, "default");
        ASSERT_NE(nullptr, default_prov);
    }

    void TearDown() override
    {
        if (nullptr != default_prov)
        {
            OSSL_PROVIDER_unload(default_prov);
        }
        if (nullptr != mpss_prov)
        {
            OSSL_PROVIDER_unload(mpss_prov);
        }
        if (nullptr != libctx)
        {
            OSSL_LIB_CTX_free(libctx);
        }
    }

    // Open "mpss:<key_name>" through OSSL_STORE, optionally selecting a backend via the mpss_backend
    // ctx parameter, and return the reopened key (or nullptr if none was produced).
    EVP_PKEY *store_open_key(const std::string &key_name, const char *backend)
    {
        const std::string uri = "mpss:" + key_name;
        OSSL_PARAM backend_params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(nullptr != backend ? backend : ""), 0),
            OSSL_PARAM_construct_end()};
        OSSL_STORE_CTX *store = OSSL_STORE_open_ex(uri.c_str(), libctx, "provider=mpss", nullptr, nullptr,
                                                   nullptr != backend ? backend_params : nullptr, nullptr, nullptr);
        if (nullptr == store)
        {
            return nullptr;
        }
        EVP_PKEY *pkey = nullptr;
        while (0 == OSSL_STORE_eof(store))
        {
            OSSL_STORE_INFO *info = OSSL_STORE_load(store);
            if (nullptr == info)
            {
                continue;
            }
            if (OSSL_STORE_INFO_PKEY == OSSL_STORE_INFO_get_type(info))
            {
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
            }
            OSSL_STORE_INFO_free(info);
        }
        OSSL_STORE_close(store);
        return pkey;
    }

    // Delete "mpss:<key_name>" through OSSL_STORE_delete, optionally selecting a backend via the
    // mpss_backend parameter. Returns the OSSL_STORE_delete result (1 on success, 0 otherwise).
    int store_delete_key(const std::string &key_name, const char *backend)
    {
        const std::string uri = "mpss:" + key_name;
        OSSL_PARAM backend_params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(nullptr != backend ? backend : ""), 0),
            OSSL_PARAM_construct_end()};
        return OSSL_STORE_delete(uri.c_str(), libctx, "provider=mpss", nullptr, nullptr,
                                 nullptr != backend ? backend_params : nullptr);
    }

    // Create a key (optionally on an explicit backend / with a key policy), close it, reopen it by
    // name through OSSL_STORE, and prove the reopened handle is the same key (identical SPKI) and
    // usable (its signature verifies under the default provider against the created key's public key).
    void reopen_roundtrip(const char *key_name, const char *backend, std::uint64_t key_policy)
    {
        const bool from_backend = (nullptr != backend);
        if (from_backend)
        {
            mpss_delete_key_from_backend(key_name, backend);
        }
        else
        {
            mpss_delete_key(key_name);
        }

        // Create and capture the public key (SubjectPublicKeyInfo DER).
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss");
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
        std::uint64_t policy = key_policy;
        OSSL_PARAM gen_params[6];
        std::size_t n = 0;
        gen_params[n++] = OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0);
        gen_params[n++] =
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0);
        if (from_backend)
        {
            gen_params[n++] = OSSL_PARAM_construct_utf8_string("mpss_backend", const_cast<char *>(backend), 0);
        }
        if (MPSS_KEY_POLICY_NONE != key_policy)
        {
            gen_params[n++] = OSSL_PARAM_construct_uint64("mpss_key_policy", &policy);
        }
        gen_params[n] = OSSL_PARAM_construct_end();
        ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, gen_params));
        EVP_PKEY *pkey = nullptr;
        ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
        ASSERT_NE(nullptr, pkey);
        EVP_PKEY_CTX_free(ctx);

        unsigned char *spki_created = nullptr;
        const int spki_created_len = i2d_PUBKEY(pkey, &spki_created);
        ASSERT_GT(spki_created_len, 0);
        EVP_PKEY_free(pkey); // close

        // Reopen by name (selecting the backend when one was given).
        EVP_PKEY *reopened = store_open_key(key_name, backend);
        ASSERT_NE(nullptr, reopened);

        // Identity: the reopened key exposes the same public key as the created one.
        unsigned char *spki_reopened = nullptr;
        const int spki_reopened_len = i2d_PUBKEY(reopened, &spki_reopened);
        ASSERT_GT(spki_reopened_len, 0);
        ASSERT_EQ(spki_created_len, spki_reopened_len);
        ASSERT_EQ(0, memcmp(spki_created, spki_reopened, static_cast<std::size_t>(spki_created_len)));

        // Usability: sign with the reopened key, verify under the default provider against the
        // captured public key.
        const std::string_view message = "reopened key signing test";
        const auto *msg = reinterpret_cast<const unsigned char *>(message.data());
        EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, sign_ctx);
        ASSERT_EQ(1, EVP_DigestSignInit_ex(sign_ctx, nullptr, "SHA256", libctx, "provider=mpss", reopened, nullptr));
        std::size_t sig_len = 0;
        ASSERT_EQ(1, EVP_DigestSign(sign_ctx, nullptr, &sig_len, msg, message.size()));
        std::vector<unsigned char> sig(sig_len);
        ASSERT_EQ(1, EVP_DigestSign(sign_ctx, sig.data(), &sig_len, msg, message.size()));
        sig.resize(sig_len);
        EVP_MD_CTX_free(sign_ctx);

        const unsigned char *spki_ptr = spki_created;
        EVP_PKEY *verify_key = d2i_PUBKEY_ex(nullptr, &spki_ptr, spki_created_len, libctx, "provider=default");
        ASSERT_NE(nullptr, verify_key);
        EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();
        ASSERT_NE(nullptr, verify_ctx);
        ASSERT_EQ(
            1, EVP_DigestVerifyInit_ex(verify_ctx, nullptr, "SHA256", libctx, "provider=default", verify_key, nullptr));
        ASSERT_EQ(1, EVP_DigestVerify(verify_ctx, sig.data(), sig.size(), msg, message.size()));
        EVP_MD_CTX_free(verify_ctx);

        EVP_PKEY_free(verify_key);
        EVP_PKEY_free(reopened);
        OPENSSL_free(spki_created);
        OPENSSL_free(spki_reopened);

        // The mpss_backend parameter must actually be consulted, not silently ignored: opening the
        // (still-present) key with a nonexistent backend must fail closed rather than fall back to
        // the default backend. This is what distinguishes routing from defaulting when the target
        // backend happens to be the default (e.g. "os" on macOS).
        if (from_backend)
        {
            ASSERT_EQ(nullptr, store_open_key(key_name, "nonexistent"));
        }

        // Delete through the OSSL-native path (OSSL_STORE_delete), selecting the backend when given.
        ASSERT_EQ(1, store_delete_key(key_name, backend));
    }
};

TEST_F(MPSSStore, ReopenByNameDefaultBackend)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    reopen_roundtrip("test_key_reopen_by_name", nullptr, MPSS_KEY_POLICY_NONE);
    ASSERT_FALSE(HasFatalFailure());

    // A deleted / nonexistent name yields no key: the store delivers the reference object, but key
    // management load fails to open it, so nothing is produced.
    ASSERT_EQ(nullptr, store_open_key("test_key_reopen_by_name", nullptr));

    // A URI with an empty key name is rejected when the store is opened.
    ASSERT_EQ(nullptr,
              OSSL_STORE_open_ex("mpss:", libctx, "provider=mpss", nullptr, nullptr, nullptr, nullptr, nullptr));
}

TEST_F(MPSSStore, ReopenByNameExplicitBackendOS)
{
    if (!mpss_is_algorithm_available_in_backend("ecdsa_secp256r1_sha256", "os"))
    {
        GTEST_SKIP() << "os backend not available";
    }

    // Selecting the backend explicitly through the mpss_backend store parameter must reopen the same
    // key that key generation created on that backend.
    reopen_roundtrip("test_key_reopen_os", "os", MPSS_KEY_POLICY_NONE);
}

TEST_F(MPSSStore, DeleteByName)
{
    if (!mpss_is_algorithm_available("ecdsa_secp256r1_sha256"))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *key_name = "test_key_delete_by_name";
    mpss_delete_key(key_name);

    // Create a key on the default backend.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM gen_params[] = {
        OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name), 0),
        OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>("ecdsa_secp256r1_sha256"), 0),
        OSSL_PARAM_construct_end()};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, gen_params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Delete it through OSSL_STORE_delete, then confirm it is gone and a second delete fails.
    ASSERT_EQ(1, store_delete_key(key_name, nullptr));
    ASSERT_EQ(nullptr, store_open_key(key_name, nullptr));
    ASSERT_EQ(0, store_delete_key(key_name, nullptr));
}

#ifdef MPSS_BACKEND_YUBIKEY
TEST_F(MPSSStore, ReopenByNameYubiKey)
{
    if (!mpss_is_algorithm_available_in_backend("ecdsa_secp256r1_sha256", "yubikey"))
    {
        GTEST_SKIP() << "YubiKey backend/device not available";
    }

    // touch=never so signing does not block on a physical touch during automated runs; pin=once uses
    // the configured PIN (MPSS_YUBIKEY_PIN) for the signing operation.
    reopen_roundtrip("test_key_reopen_yk", "yubikey",
                     MPSS_KEY_POLICY_YUBIKEY_TOUCH_NEVER | MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE);
}
#endif // MPSS_BACKEND_YUBIKEY

class CreateAndDeleteKeyTest : public ::testing::TestWithParam<const char *>
{
};

TEST_P(CreateAndDeleteKeyTest, CreateAndDeleteKey)
{
    const char *mpss_algorithm = GetParam();
    if (!mpss_is_algorithm_available(mpss_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend: " << mpss_algorithm;
    }

    std::string key_name = "test_create_delete_key_";
    key_name.append(mpss_algorithm);

    // Delete existing key.
    const bool _ = mpss_delete_key(key_name.c_str());

    OSSL_LIB_CTX *mpss_libctx = OSSL_LIB_CTX_new();
    ASSERT_NE(nullptr, mpss_libctx);
    ASSERT_NE(0, OSSL_PROVIDER_add_builtin(mpss_libctx, "mpss", OSSL_provider_init));
    OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(mpss_libctx, "mpss");
    ASSERT_NE(nullptr, mpss_prov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss");
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(ctx));
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0),
                           OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(mpss_algorithm), 0),
                           OSSL_PARAM_END};
    ASSERT_EQ(1, EVP_PKEY_CTX_set_params(ctx, params));
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(1, EVP_PKEY_generate(ctx, &pkey));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Now delete the key using the API.
    ASSERT_EQ(1, mpss_delete_key(key_name.c_str()));
    ASSERT_NE(0, OSSL_PROVIDER_unload(mpss_prov));
    OSSL_LIB_CTX_free(mpss_libctx);
}

INSTANTIATE_TEST_SUITE_P(MPSSCreateDelete, CreateAndDeleteKeyTest,
                         ::testing::Values("ECDSA with P256 and SHA2-256", "ECDSA with P384 and SHA2-384",
                                           "ECDSA with P521 and SHA2-512"),
                         [](const ::testing::TestParamInfo<const char *> &info) {
                             std::string name(info.param);
                             std::ranges::replace_if(name, [](char c) { return !std::isalnum(c); }, '_');
                             return name;
                         });

} // namespace mpss_openssl::tests
