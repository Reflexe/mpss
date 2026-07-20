// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/utils.h"
#include "mpss/key_policy.h"
#include "openssl_raii.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

constexpr const char *mpss_p256_algorithm = "ecdsa_secp256r1_sha256";

using mpss_openssl::testing::BioPtr;
using mpss_openssl::testing::EncoderCtxPtr;
using mpss_openssl::testing::EvpPkeyCtxPtr;
using mpss_openssl::testing::EvpPkeyPtr;
using mpss_openssl::testing::X509ReqPtr;

bool HasParam(const OSSL_PARAM *params, const char *name)
{
    return nullptr != params && nullptr != OSSL_PARAM_locate_const(params, name);
}

std::vector<unsigned char> ToUnsignedBytes(const std::vector<std::byte> &bytes)
{
    std::vector<unsigned char> out;
    out.reserve(bytes.size());
    for (std::byte byte : bytes)
    {
        out.push_back(std::to_integer<unsigned char>(byte));
    }
    return out;
}

class MPSSProvider : public ::testing::Test
{
  protected:
    OSSL_LIB_CTX *mpss_libctx = nullptr;
    OSSL_PROVIDER *mpss_prov = nullptr;
    OSSL_PROVIDER *default_prov = nullptr;
    std::vector<std::string> key_names;

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
        for (const std::string &key_name : key_names)
        {
            mpss_delete_key(key_name.c_str());
        }

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

    std::string MakeKeyName(std::string_view label)
    {
        static std::atomic<std::uint64_t> counter{0};
        const auto ticks = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());

        // Backends cap key names at 64 characters, so keep the generated name well under that:
        // a short prefix, a truncated label, and a compact uniqueness suffix (a monotonic
        // counter plus the low digits of the clock so names stay distinct across test runs).
        std::string key_name = "mpss_ossl_" + std::string(label.substr(0, 16)) + "_" +
                               std::to_string(ticks % 1000000000000ULL) + "_" + std::to_string(++counter);
        mpss_delete_key(key_name.c_str());
        key_names.push_back(key_name);
        return key_name;
    }

    EvpPkeyPtr GenerateKey(const std::string &key_name)
    {
        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss"));
        if (nullptr == ctx || 1 != EVP_PKEY_keygen_init(ctx.get()))
        {
            return nullptr;
        }

        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(mpss_p256_algorithm), 0),
            OSSL_PARAM_END};
        if (1 != EVP_PKEY_CTX_set_params(ctx.get(), params))
        {
            return nullptr;
        }

        EVP_PKEY *pkey = nullptr;
        if (1 != EVP_PKEY_generate(ctx.get(), &pkey))
        {
            return nullptr;
        }
        return EvpPkeyPtr(pkey);
    }

    EvpPkeyPtr GenerateNamedKey(const std::string &key_name, const char *algorithm)
    {
        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(mpss_libctx, "EC", "provider=mpss"));
        if (nullptr == ctx || 1 != EVP_PKEY_keygen_init(ctx.get()))
        {
            return nullptr;
        }

        OSSL_PARAM params[3];
        int count = 0;
        params[count++] = OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0);
        if (nullptr != algorithm)
        {
            params[count++] = OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(algorithm), 0);
        }
        params[count] = OSSL_PARAM_construct_end();
        if (1 != EVP_PKEY_CTX_set_params(ctx.get(), params))
        {
            return nullptr;
        }

        EVP_PKEY *pkey = nullptr;
        if (1 != EVP_PKEY_generate(ctx.get(), &pkey))
        {
            return nullptr;
        }
        return EvpPkeyPtr(pkey);
    }

    std::string ReferencePemFromBody(const std::vector<std::byte> &body)
    {
        if (body.empty() || !std::in_range<int>(body.size()))
        {
            return {};
        }

        std::vector<unsigned char> encoded(4 * ((body.size() + 2) / 3) + 1);
        const int encoded_size =
            EVP_EncodeBlock(encoded.data(), reinterpret_cast<const unsigned char *>(body.data()),
                            static_cast<int>(body.size()));
        if (encoded_size <= 0)
        {
            return {};
        }

        std::string pem = "-----BEGIN ";
        pem += mpss_openssl::provider::mpss_key_reference_pem_label;
        pem += "-----\n";
        const std::string base64(reinterpret_cast<const char *>(encoded.data()), static_cast<std::size_t>(encoded_size));
        for (std::size_t offset = 0; offset < base64.size(); offset += 64)
        {
            pem.append(base64, offset, std::min<std::size_t>(64, base64.size() - offset));
            pem.push_back('\n');
        }
        pem += "-----END ";
        pem += mpss_openssl::provider::mpss_key_reference_pem_label;
        pem += "-----\n";
        return pem;
    }

    bool ReadReferencePemBody(const std::string &pem, std::vector<std::byte> &body)
    {
        BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
        if (nullptr == bio)
        {
            return false;
        }

        char *name = nullptr;
        char *header = nullptr;
        unsigned char *data = nullptr;
        long size = 0;
        const int ok = PEM_read_bio(bio.get(), &name, &header, &data, &size);
        const mpss_openssl::utils::openssl_ptr<char> name_owner(name);
        const mpss_openssl::utils::openssl_ptr<char> header_owner(header);
        const mpss_openssl::utils::openssl_ptr<unsigned char> data_owner(data);
        const bool is_reference = 1 == ok && nullptr != name &&
                                  0 == std::strcmp(name, mpss_openssl::provider::mpss_key_reference_pem_label) &&
                                  size >= 0;
        if (is_reference)
        {
            body.assign(reinterpret_cast<const std::byte *>(data), reinterpret_cast<const std::byte *>(data + size));
        }

        return is_reference;
    }

    EvpPkeyPtr DecodeReferencePem(const std::string &pem)
    {
        BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
        if (nullptr == bio)
        {
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey_ex(bio.get(), nullptr, nullptr, nullptr, mpss_libctx, "provider=mpss");
        return EvpPkeyPtr(pkey);
    }

    std::string EncodeReferencePem(EVP_PKEY *key, int selection = EVP_PKEY_PRIVATE_KEY)
    {
        EncoderCtxPtr encoder(
            OSSL_ENCODER_CTX_new_for_pkey(key, selection, "PEM", "MpssKeyReference", "provider=mpss"));
        if (nullptr == encoder || OSSL_ENCODER_CTX_get_num_encoders(encoder.get()) <= 0)
        {
            return {};
        }

        BioPtr bio(BIO_new(BIO_s_mem()));
        if (nullptr == bio || 1 != OSSL_ENCODER_to_bio(encoder.get(), bio.get()))
        {
            return {};
        }

        char *data = nullptr;
        const long size = BIO_get_mem_data(bio.get(), &data);
        if (size <= 0 || nullptr == data)
        {
            return {};
        }
        return {data, static_cast<std::size_t>(size)};
    }

    std::vector<unsigned char> SignDigest(EVP_PKEY *key)
    {
        constexpr std::array<unsigned char, 32> digest{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(mpss_libctx, key, "provider=mpss"));
        if (nullptr == ctx || 1 != EVP_PKEY_sign_init(ctx.get()))
        {
            return {};
        }

        std::size_t sig_len = 0;
        if (1 != EVP_PKEY_sign(ctx.get(), nullptr, &sig_len, digest.data(), digest.size()) || 0 == sig_len)
        {
            return {};
        }

        std::vector<unsigned char> signature(sig_len);
        if (1 != EVP_PKEY_sign(ctx.get(), signature.data(), &sig_len, digest.data(), digest.size()))
        {
            return {};
        }
        signature.resize(sig_len);
        return signature;
    }
};

} // namespace

namespace mpss_openssl::tests
{

// Scenario: a key created with an algorithm is reopened through the keymgmt gen path by name only.
// Expected behavior: reopening the existing key by name without specifying an algorithm succeeds and
// returns the originally created key (same group), instead of failing because no algorithm was given.
TEST_F(MPSSProvider, KeymgmtGenReopensExistingKeyByNameWithoutAlgorithm)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = MakeKeyName("gen_reopen");
    EvpPkeyPtr created = GenerateNamedKey(key_name, mpss_p256_algorithm);
    if (nullptr == created)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    // Reopening the existing key by name without specifying an algorithm succeeds and yields the
    // originally created key (same group).
    EvpPkeyPtr reopened = GenerateNamedKey(key_name, nullptr);
    ASSERT_NE(nullptr, reopened) << "reopen by name without an algorithm failed: " << mpss_get_error();
    char group_name[80] = {};
    std::size_t group_name_len = 0;
    ASSERT_EQ(1, EVP_PKEY_get_group_name(reopened.get(), group_name, sizeof(group_name), &group_name_len));
    EXPECT_STREQ(SN_X9_62_prime256v1, group_name);
}

// Scenario: the MPSS provider signs an X.509 request with ECDSA P-256/SHA-256.
// Expected behavior: the signature AlgorithmIdentifier uses ecdsa-with-SHA256 with absent parameters.
TEST_F(MPSSProvider, EcdsaSignatureAlgorithmIdentifierOmitsParameters)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = MakeKeyName("algid");
    EvpPkeyPtr pkey = GenerateKey(key_name);
    if (nullptr == pkey)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    X509ReqPtr req(X509_REQ_new());
    ASSERT_NE(nullptr, req);
    ASSERT_EQ(1, X509_REQ_set_version(req.get(), 0L));
    ASSERT_EQ(1, X509_REQ_set_pubkey(req.get(), pkey.get()));

    // Fetch SHA-256 from this fixture's libctx so the whole sign path stays in one OSSL_LIB_CTX.
    EVP_MD *sha256 = EVP_MD_fetch(mpss_libctx, "SHA256", nullptr);
    ASSERT_NE(nullptr, sha256);
    const int sign_rc = X509_REQ_sign(req.get(), pkey.get(), sha256);
    EVP_MD_free(sha256);
    ASSERT_GT(sign_rc, 0);

    // Coverage: a signature emitted with absent AlgorithmIdentifier parameters must still verify.
    EXPECT_EQ(1, X509_REQ_verify(req.get(), pkey.get()));

    const ASN1_BIT_STRING *signature = nullptr;
    const X509_ALGOR *algorithm = nullptr;
    X509_REQ_get0_signature(req.get(), &signature, &algorithm);
    ASSERT_NE(nullptr, signature);
    ASSERT_GT(ASN1_STRING_length(signature), 0);
    ASSERT_NE(nullptr, algorithm);

    const ASN1_OBJECT *algorithm_object = nullptr;
    int parameter_type = V_ASN1_UNDEF;
    const void *parameter_value = nullptr;
    X509_ALGOR_get0(&algorithm_object, &parameter_type, &parameter_value, algorithm);
    ASSERT_NE(nullptr, algorithm_object);
    EXPECT_EQ(NID_ecdsa_with_SHA256, OBJ_obj2nid(algorithm_object));
    EXPECT_EQ(V_ASN1_UNDEF, parameter_type);
    EXPECT_EQ(nullptr, parameter_value);
}

// Scenario: an MPSS key is exported through the public EVP data API with each subset selection.
// Expected behavior: export yields exactly the components named by the selection and never the private key.
TEST_F(MPSSProvider, KeymgmtExportHonorsSelection)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = MakeKeyName("export_select");
    EvpPkeyPtr pkey = GenerateKey(key_name);
    if (nullptr == pkey)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    // Empty selection: neither component is exported.
    OSSL_PARAM *none = nullptr;
    EVP_PKEY_todata(pkey.get(), 0, &none);
    EXPECT_FALSE(HasParam(none, OSSL_PKEY_PARAM_PUB_KEY));
    EXPECT_FALSE(HasParam(none, OSSL_PKEY_PARAM_GROUP_NAME));
    OSSL_PARAM_free(none);

    // Parameters only: the group name, but not the public key.
    OSSL_PARAM *params = nullptr;
    ASSERT_EQ(1, EVP_PKEY_todata(pkey.get(), OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, &params));
    EXPECT_TRUE(HasParam(params, OSSL_PKEY_PARAM_GROUP_NAME));
    EXPECT_FALSE(HasParam(params, OSSL_PKEY_PARAM_PUB_KEY));
    OSSL_PARAM_free(params);

    // Public key only: the public key, but not the group name.
    OSSL_PARAM *pub = nullptr;
    ASSERT_EQ(1, EVP_PKEY_todata(pkey.get(), OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &pub));
    EXPECT_TRUE(HasParam(pub, OSSL_PKEY_PARAM_PUB_KEY));
    EXPECT_FALSE(HasParam(pub, OSSL_PKEY_PARAM_GROUP_NAME));
    OSSL_PARAM_free(pub);

    // Public key and parameters together: both components.
    OSSL_PARAM *both = nullptr;
    ASSERT_EQ(1, EVP_PKEY_todata(pkey.get(), OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                                 &both));
    EXPECT_TRUE(HasParam(both, OSSL_PKEY_PARAM_PUB_KEY));
    EXPECT_TRUE(HasParam(both, OSSL_PKEY_PARAM_GROUP_NAME));
    OSSL_PARAM_free(both);

    // A keypair request never releases private-key material. Do not rely on EVP_PKEY_todata's exact
    // refusal semantics; assert only that no private key is ever returned.
    OSSL_PARAM *keypair = nullptr;
    EVP_PKEY_todata(pkey.get(), EVP_PKEY_KEYPAIR, &keypair);
    EXPECT_FALSE(HasParam(keypair, OSSL_PKEY_PARAM_PRIV_KEY));
    OSSL_PARAM_free(keypair);
}

// Scenario: OpenSSL asks an MPSS EC key for its standard group name parameter.
// Expected behavior: OSSL_PKEY_PARAM_GROUP_NAME is gettable and returns prime256v1.
TEST_F(MPSSProvider, KeymgmtAdvertisesGroupName)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = MakeKeyName("group_name");
    EvpPkeyPtr pkey = GenerateKey(key_name);
    if (nullptr == pkey)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    const OSSL_PARAM *gettable = EVP_PKEY_gettable_params(pkey.get());
    ASSERT_NE(nullptr, gettable);
    EXPECT_TRUE(HasParam(gettable, OSSL_PKEY_PARAM_GROUP_NAME));

    char group_name[80] = {};
    std::size_t group_name_len = 0;
    ASSERT_EQ(1, EVP_PKEY_get_group_name(pkey.get(), group_name, sizeof(group_name), &group_name_len));
    EXPECT_STREQ(SN_X9_62_prime256v1, group_name);
    EXPECT_EQ(std::strlen(group_name), group_name_len);
}

// Scenario: OpenSSL decodes an MPSS reference PEM for a persisted key, and malformed references are supplied.
// Expected behavior: the valid reference reopens the named key (usable for signing) and malformed or foreign
// PEM inputs decode to no key.
TEST_F(MPSSProvider, ReferencePemDecoderReopensKeyByNameAndRejectsMalformedInput)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = MakeKeyName("reference_decode");
    EvpPkeyPtr key = GenerateKey(key_name);
    if (nullptr == key)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }
    key.reset();

    // The reference names the persisted key; decoding it reopens the key by name for use.
    std::vector<std::byte> body;
    ASSERT_TRUE(mpss_openssl::provider::mpss_build_key_reference_body(key_name, body));
    const std::string pem = ReferencePemFromBody(body);
    ASSERT_FALSE(pem.empty());
    EvpPkeyPtr decoded = DecodeReferencePem(pem);
    ASSERT_NE(nullptr, decoded.get());
    EXPECT_FALSE(SignDigest(decoded.get()).empty());

    // A reference naming a key that does not exist decodes to no key.
    std::vector<std::byte> unknown_body;
    ASSERT_TRUE(mpss_openssl::provider::mpss_build_key_reference_body(MakeKeyName("never_decoded"), unknown_body));
    const std::string unknown_pem = ReferencePemFromBody(unknown_body);
    ASSERT_FALSE(unknown_pem.empty());
    EXPECT_EQ(nullptr, DecodeReferencePem(unknown_pem).get());

    // An oversized PEM body is declined by the decoder.
    const std::vector<std::byte> oversized_body(
        mpss_openssl::provider::mpss_key_reference_max_encoded_size + 1, std::byte{0x41});
    const std::string oversized_pem = ReferencePemFromBody(oversized_body);
    ASSERT_FALSE(oversized_pem.empty());
    EXPECT_EQ(nullptr, DecodeReferencePem(oversized_pem).get());

    // A foreign (non-MPSS) PEM must not decode to an MPSS key.
    const std::string foreign_pem =
        "-----BEGIN PRIVATE KEY-----\n"
        "TUVTU0FHRQ==\n"
        "-----END PRIVATE KEY-----\n";
    EXPECT_EQ(nullptr, DecodeReferencePem(foreign_pem).get());
}

// Scenario: the reference binary codec round-trips a key name.
// Expected behavior: parsing a freshly built body recovers the exact name.
TEST(ReferenceCodec, BuildParseRoundTrip)
{
    using namespace mpss_openssl::provider;
    const std::string name = "codec-roundtrip";

    mpss_openssl::utils::byte_vector body;
    ASSERT_TRUE(mpss_build_key_reference_body(name, body));

    const std::vector<unsigned char> body_bytes = ToUnsignedBytes(body);
    mpss_key_reference parsed;
    ASSERT_TRUE(mpss_parse_key_reference_body(body_bytes, parsed));
    EXPECT_EQ(name, parsed.key_name);
}

// Scenario: mpss_build_key_reference_body rejects arguments it cannot encode.
// Expected behavior: an empty name, an over-cap name, and a name with an embedded NUL all fail.
TEST(ReferenceCodec, BuildRejectsInvalidArguments)
{
    using namespace mpss_openssl::provider;

    mpss_openssl::utils::byte_vector body;
    EXPECT_FALSE(mpss_build_key_reference_body("", body));
    EXPECT_FALSE(mpss_build_key_reference_body(std::string(mpss_key_reference_max_name_len + 1, 'a'), body));

    const std::string embedded_nul("ab\0cd", 5);
    EXPECT_FALSE(mpss_build_key_reference_body(embedded_nul, body));
}

// Scenario: mpss_parse_key_reference_body validates untrusted input before trusting it as a name.
// Expected behavior: an empty body, an over-cap body, and a body with an embedded NUL are rejected.
// This backend-independent path is what the Linux ASan+UBSan job exercises on the parser.
TEST(ReferenceCodec, ParseRejectsMalformedBodies)
{
    using namespace mpss_openssl::provider;
    mpss_key_reference out;

    EXPECT_FALSE(mpss_parse_key_reference_body(std::span<const unsigned char>{}, out));

    const std::vector<unsigned char> over_cap(mpss_key_reference_max_name_len + 1, 'a');
    EXPECT_FALSE(mpss_parse_key_reference_body(over_cap, out));

    const std::vector<unsigned char> embedded_nul = {'a', 'b', '\0', 'c', 'd'};
    EXPECT_FALSE(mpss_parse_key_reference_body(embedded_nul, out));
}

// Scenario: a reference at the maximum permitted name size round-trips.
// Expected behavior: build + parse succeeds and recovers the exact bytes (also the ASan reach).
TEST(ReferenceCodec, MaxSizeBodyRoundTrip)
{
    using namespace mpss_openssl::provider;
    const std::string name(mpss_key_reference_max_name_len, 'n');

    mpss_openssl::utils::byte_vector body;
    ASSERT_TRUE(mpss_build_key_reference_body(name, body));
    EXPECT_EQ(name.size(), body.size());

    mpss_key_reference parsed;
    ASSERT_TRUE(mpss_parse_key_reference_body(ToUnsignedBytes(body), parsed));
    EXPECT_EQ(name, parsed.key_name);
}

// Scenario: the MPSS encoder serializes a persisted provider key as a name-bearing reference PEM.
// Expected behavior: the reference carries the key name and round-trips through the MPSS decoder.
TEST_F(MPSSProvider, ReferencePemEncoderCarriesNameAndRoundTrips)
{
    if (!mpss_is_algorithm_available(mpss_p256_algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = MakeKeyName("reference_encode");
    EvpPkeyPtr key = GenerateKey(key_name);
    if (nullptr == key)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    const std::string pem = EncodeReferencePem(key.get());
    ASSERT_FALSE(pem.empty());
    EXPECT_NE(std::string::npos, pem.find(mpss_openssl::provider::mpss_key_reference_pem_label));
    EXPECT_EQ(std::string::npos, pem.find("PRIVATE KEY"));

    std::vector<std::byte> pem_body;
    ASSERT_TRUE(ReadReferencePemBody(pem, pem_body));
    mpss_openssl::provider::mpss_key_reference parsed_pem;
    ASSERT_TRUE(mpss_openssl::provider::mpss_parse_key_reference_body(ToUnsignedBytes(pem_body), parsed_pem));
    EXPECT_EQ(key_name, parsed_pem.key_name);

    // Coverage: the reference PEM encoder advertises only the private-key selection, so encoding a
    // public-key-only selection through the public OSSL_ENCODER API yields no reference PEM - the
    // mechanism that keeps public-key material out of the reference path.
    EXPECT_TRUE(EncodeReferencePem(key.get(), EVP_PKEY_PUBLIC_KEY).empty());

    key.reset();
    EvpPkeyPtr decoded = DecodeReferencePem(pem);
    ASSERT_NE(nullptr, decoded.get());
    EXPECT_FALSE(SignDigest(decoded.get()).empty());
}

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
