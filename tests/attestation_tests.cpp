// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/attestation.h"
#include "mpss/impl/apple/attestation_policy.h"
#include "mpss/mpss.h"
#include "mpss/utils/scope_guard.h"
#include "tests/mock_pki/mock_pki.h"
#include <gtest/gtest.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mpss::tests
{

namespace
{

using EVPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVPKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509ExtensionPtr = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using ASN1OctetStringPtr = std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>;
using ASN1ObjectPtr = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;

const char *AttestationFormatName(AttestationFormat format)
{
    switch (format)
    {
    case AttestationFormat::none:
        return "none";
    case AttestationFormat::apple_app_attest:
        return "apple_app_attest";
    case AttestationFormat::apple_acme_managed_device_attestation:
        return "apple_acme_managed_device_attestation";
    case AttestationFormat::android_key_attestation:
        return "android_key_attestation";
    case AttestationFormat::windows_vbs:
        return "windows_vbs";
    case AttestationFormat::windows_tpm:
        return "windows_tpm";
    }
    return "unknown";
}

std::vector<std::byte> BuildStatement(std::string_view prefix, std::span<const std::byte> challenge,
                                      std::span<const std::byte> public_key)
{
    std::vector<std::byte> statement;
    statement.reserve(prefix.size() + challenge.size() + public_key.size() + 2);
    for (char c : prefix)
    {
        statement.push_back(static_cast<std::byte>(c));
    }
    statement.push_back(static_cast<std::byte>(challenge.size() & 0xFFU));
    statement.insert(statement.end(), challenge.begin(), challenge.end());
    statement.push_back(static_cast<std::byte>(public_key.size() & 0xFFU));
    statement.insert(statement.end(), public_key.begin(), public_key.end());
    return statement;
}

std::vector<std::byte> BuildAppleAppAttestStatement(std::span<const std::byte> challenge,
                                                    std::span<const std::byte> public_key)
{
    static constexpr std::string_view prefix = "MPSS_APP_ATTEST_V1";
    std::vector<std::byte> statement;
    statement.reserve(prefix.size() + challenge.size() + sizeof(std::size_t));
    for (char c : prefix)
    {
        statement.push_back(static_cast<std::byte>(c));
    }
    statement.insert(statement.end(), challenge.begin(), challenge.end());

    const std::string key_material(reinterpret_cast<const char *>(public_key.data()), public_key.size());
    const std::size_t binding = std::hash<std::string>{}(key_material);
    for (std::size_t i = 0; i < sizeof(binding); ++i)
    {
        statement.push_back(static_cast<std::byte>((binding >> (i * 8U)) & 0xFFU));
    }
    return statement;
}

// Build a minimal DER encoding of the Android KeyDescription SEQUENCE, embedding
// `challenge` as the attestationChallenge OCTET STRING (field 4, zero-indexed).
//
//   KeyDescription ::= SEQUENCE {
//     attestationVersion         INTEGER 4,
//     attestationSecurityLevel   ENUMERATED 1 (SOFTWARE),
//     keymasterVersion           INTEGER 100,
//     keymasterSecurityLevel     ENUMERATED 1 (SOFTWARE),
//     attestationChallenge       OCTET STRING,   <-- challenge embedded here
//     uniqueId                   OCTET STRING (empty),
//     softwareEnforced           SEQUENCE {},
//     hardwareEnforced           SEQUENCE {},
//   }
//
// Note: emulator builds produce SOFTWARE security level; this does not prove
// hardware backing but allows the challenge-binding to be validated end-to-end.
std::vector<unsigned char> BuildAndroidKeyDescriptionDer(std::span<const std::byte> challenge)
{
    // Helper to append a DER length field (short or multi-byte form).
    const auto append_length = [](std::vector<unsigned char> &buf, std::size_t len) {
        if (len < 0x80U)
        {
            buf.push_back(static_cast<unsigned char>(len));
        }
        else if (len < 0x100U)
        {
            buf.push_back(0x81U);
            buf.push_back(static_cast<unsigned char>(len));
        }
        else
        {
            buf.push_back(0x82U);
            buf.push_back(static_cast<unsigned char>((len >> 8U) & 0xFFU));
            buf.push_back(static_cast<unsigned char>(len & 0xFFU));
        }
    };

    std::vector<unsigned char> content;
    // attestationVersion  INTEGER 4
    content.insert(content.end(), {0x02, 0x01, 0x04});
    // attestationSecurityLevel  ENUMERATED 1 (SOFTWARE)
    content.insert(content.end(), {0x0A, 0x01, 0x01});
    // keymasterVersion  INTEGER 100
    content.insert(content.end(), {0x02, 0x01, 0x64});
    // keymasterSecurityLevel  ENUMERATED 1 (SOFTWARE)
    content.insert(content.end(), {0x0A, 0x01, 0x01});
    // attestationChallenge  OCTET STRING
    content.push_back(0x04);
    append_length(content, challenge.size());
    for (const auto b : challenge)
    {
        content.push_back(static_cast<unsigned char>(b));
    }
    // uniqueId  OCTET STRING (empty)
    content.insert(content.end(), {0x04, 0x00});
    // softwareEnforced  SEQUENCE (empty)
    content.insert(content.end(), {0x30, 0x00});
    // hardwareEnforced  SEQUENCE (empty)
    content.insert(content.end(), {0x30, 0x00});

    // Wrap in outer SEQUENCE.
    std::vector<unsigned char> result;
    result.push_back(0x30);
    append_length(result, content.size());
    result.insert(result.end(), content.begin(), content.end());
    return result;
}

// Add the Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) to `cert`.
// Must be called before the certificate is signed.
// The extension value is the DER encoding of KeyDescription with `challenge` embedded.
bool AddAndroidAttestationExtension(X509 *cert, std::span<const std::byte> challenge)
{
    const auto key_desc_der = BuildAndroidKeyDescriptionDer(challenge);

    ASN1ObjectPtr oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1), ASN1_OBJECT_free);
    if (nullptr == oid)
    {
        return false;
    }

    ASN1OctetStringPtr ext_val(ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
    if (nullptr == ext_val)
    {
        return false;
    }
    if (1 != ASN1_OCTET_STRING_set(ext_val.get(),
                                    reinterpret_cast<const unsigned char *>(key_desc_der.data()),
                                    static_cast<int>(key_desc_der.size())))
    {
        return false;
    }

    X509ExtensionPtr ext(X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0, ext_val.get()),
                         X509_EXTENSION_free);
    if (nullptr == ext)
    {
        return false;
    }

    return 1 == X509_add_ext(cert, ext.get(), -1);
}

std::string_view StatementPrefixForFormat(AttestationFormat format)
{
    switch (format)
    {
    case AttestationFormat::windows_tpm:
        return "MPSS_WINDOWS_TPM_ATTESTATION_V1";
    case AttestationFormat::windows_vbs:
        return "MPSS_WINDOWS_VBS_ATTESTATION_V1";
    case AttestationFormat::apple_acme_managed_device_attestation:
        return "MPSS_APPLE_ACME_MDA_V1";
    default:
        return {};
    }
}

bool UsesCertificateChain(AttestationFormat format)
{
    return AttestationFormat::apple_app_attest != format;
}

EVPKeyPtr GenerateEcP256Key()
{
    EVPKeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    if (nullptr == ctx)
    {
        return EVPKeyPtr(nullptr, EVP_PKEY_free);
    }
    if (1 != EVP_PKEY_keygen_init(ctx.get()))
    {
        return EVPKeyPtr(nullptr, EVP_PKEY_free);
    }
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1))
    {
        return EVPKeyPtr(nullptr, EVP_PKEY_free);
    }

    EVP_PKEY *raw = nullptr;
    if (1 != EVP_PKEY_keygen(ctx.get(), &raw))
    {
        return EVPKeyPtr(nullptr, EVP_PKEY_free);
    }
    return EVPKeyPtr(raw, EVP_PKEY_free);
}

bool AddCertificateExtension(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509ExtensionPtr ext(X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char *>(value)), X509_EXTENSION_free);
    if (nullptr == ext)
    {
        return false;
    }
    return 1 == X509_add_ext(cert, ext.get(), -1);
}

X509Ptr CreateCertificate(EVP_PKEY *subject_key, X509 *issuer_cert, EVP_PKEY *issuer_key, std::string_view common_name,
                          bool is_ca, long serial)
{
    X509Ptr cert(X509_new(), X509_free);
    if (nullptr == cert)
    {
        return X509Ptr(nullptr, X509_free);
    }

    if (1 != X509_set_version(cert.get(), 2))
    {
        return X509Ptr(nullptr, X509_free);
    }
    if (1 != ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial))
    {
        return X509Ptr(nullptr, X509_free);
    }
    if (nullptr == X509_gmtime_adj(X509_get_notBefore(cert.get()), 0)
        || nullptr == X509_gmtime_adj(X509_get_notAfter(cert.get()), 31536000L))
    {
        return X509Ptr(nullptr, X509_free);
    }
    if (1 != X509_set_pubkey(cert.get(), subject_key))
    {
        return X509Ptr(nullptr, X509_free);
    }

    X509_NAME *subject = X509_get_subject_name(cert.get());
    if (nullptr == subject)
    {
        return X509Ptr(nullptr, X509_free);
    }
    if (1 != X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                         reinterpret_cast<const unsigned char *>(common_name.data()),
                                         static_cast<int>(common_name.size()), -1, 0))
    {
        return X509Ptr(nullptr, X509_free);
    }

    if (nullptr != issuer_cert)
    {
        if (1 != X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer_cert)))
        {
            return X509Ptr(nullptr, X509_free);
        }
    }
    else if (1 != X509_set_issuer_name(cert.get(), subject))
    {
        return X509Ptr(nullptr, X509_free);
    }

    if (is_ca)
    {
        if (!AddCertificateExtension(cert.get(), (nullptr == issuer_cert) ? cert.get() : issuer_cert, NID_basic_constraints,
                                     "critical,CA:TRUE"))
        {
            return X509Ptr(nullptr, X509_free);
        }
        if (!AddCertificateExtension(cert.get(), (nullptr == issuer_cert) ? cert.get() : issuer_cert, NID_key_usage,
                                     "critical,keyCertSign,cRLSign"))
        {
            return X509Ptr(nullptr, X509_free);
        }
    }
    else
    {
        if (!AddCertificateExtension(cert.get(), issuer_cert, NID_basic_constraints, "critical,CA:FALSE"))
        {
            return X509Ptr(nullptr, X509_free);
        }
        if (!AddCertificateExtension(cert.get(), issuer_cert, NID_key_usage, "critical,digitalSignature"))
        {
            return X509Ptr(nullptr, X509_free);
        }
    }

    EVP_PKEY *signing_key = (nullptr == issuer_key) ? subject_key : issuer_key;
    if (0 >= X509_sign(cert.get(), signing_key, EVP_sha256()))
    {
        return X509Ptr(nullptr, X509_free);
    }

    return cert;
}

std::vector<std::byte> EncodeCertificateDer(X509 *cert)
{
    const int size = i2d_X509(cert, nullptr);
    EXPECT_GT(size, 0);
    if (size <= 0)
    {
        return {};
    }

    std::vector<std::byte> der(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(der.data());
    const int written = i2d_X509(cert, &cursor);
    EXPECT_EQ(written, size);
    if (written != size)
    {
        return {};
    }
    return der;
}

std::vector<std::byte> EncodePublicKeyDer(EVP_PKEY *key)
{
    const int size = i2d_PUBKEY(key, nullptr);
    EXPECT_GT(size, 0);
    if (size <= 0)
    {
        return {};
    }

    std::vector<std::byte> der(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(der.data());
    const int written = i2d_PUBKEY(key, &cursor);
    EXPECT_EQ(written, size);
    if (written != size)
    {
        return {};
    }
    return der;
}

struct MockChainBundle
{
    std::vector<std::byte> root_der;
    std::vector<std::vector<std::byte>> chain_der;
    std::vector<std::byte> leaf_public_key_der;
};

MockChainBundle BuildMockChain(std::string_view root_cn, std::string_view intermediate_cn, std::string_view leaf_cn)
{
    EVPKeyPtr root_key = GenerateEcP256Key();
    EVPKeyPtr intermediate_key = GenerateEcP256Key();
    EVPKeyPtr leaf_key = GenerateEcP256Key();
    EXPECT_NE(nullptr, root_key);
    EXPECT_NE(nullptr, intermediate_key);
    EXPECT_NE(nullptr, leaf_key);

    X509Ptr root_cert = CreateCertificate(root_key.get(), nullptr, nullptr, root_cn, true, 1);
    EXPECT_NE(nullptr, root_cert);
    X509Ptr intermediate_cert =
        CreateCertificate(intermediate_key.get(), root_cert.get(), root_key.get(), intermediate_cn, true, 2);
    EXPECT_NE(nullptr, intermediate_cert);
    X509Ptr leaf_cert =
        CreateCertificate(leaf_key.get(), intermediate_cert.get(), intermediate_key.get(), leaf_cn, false, 3);
    EXPECT_NE(nullptr, leaf_cert);

    MockChainBundle bundle{};
    if (nullptr == root_cert || nullptr == intermediate_cert || nullptr == leaf_cert)
    {
        return bundle;
    }

    bundle.root_der = EncodeCertificateDer(root_cert.get());
    bundle.chain_der.push_back(EncodeCertificateDer(leaf_cert.get()));
    bundle.chain_der.push_back(EncodeCertificateDer(intermediate_cert.get()));
    bundle.chain_der.push_back(bundle.root_der);
    bundle.leaf_public_key_der = EncodePublicKeyDer(leaf_key.get());
    return bundle;
}

// Build a mock Android cert chain where the leaf certificate carries the Android
// Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) with `challenge`
// embedded in the attestationChallenge field.
// The extension is added before signing so the signature covers it.
MockChainBundle BuildAndroidMockChain(std::string_view root_cn, std::string_view intermediate_cn,
                                      std::string_view leaf_cn, std::span<const std::byte> challenge)
{
    EVPKeyPtr root_key = GenerateEcP256Key();
    EVPKeyPtr intermediate_key = GenerateEcP256Key();
    EVPKeyPtr leaf_key = GenerateEcP256Key();
    EXPECT_NE(nullptr, root_key);
    EXPECT_NE(nullptr, intermediate_key);
    EXPECT_NE(nullptr, leaf_key);

    X509Ptr root_cert = CreateCertificate(root_key.get(), nullptr, nullptr, root_cn, true, 1);
    EXPECT_NE(nullptr, root_cert);
    X509Ptr intermediate_cert =
        CreateCertificate(intermediate_key.get(), root_cert.get(), root_key.get(), intermediate_cn, true, 2);
    EXPECT_NE(nullptr, intermediate_cert);

    // Build leaf cert manually so we can add the Android attestation extension
    // before signing (the extension must be covered by the certificate signature).
    X509Ptr leaf_cert(X509_new(), X509_free);
    EXPECT_NE(nullptr, leaf_cert);
    if (nullptr == leaf_cert)
    {
        return {};
    }
    EXPECT_EQ(1, X509_set_version(leaf_cert.get(), 2));
    EXPECT_EQ(1, ASN1_INTEGER_set(X509_get_serialNumber(leaf_cert.get()), 3));
    EXPECT_NE(nullptr, X509_gmtime_adj(X509_get_notBefore(leaf_cert.get()), 0));
    EXPECT_NE(nullptr, X509_gmtime_adj(X509_get_notAfter(leaf_cert.get()), 31536000L));
    EXPECT_EQ(1, X509_set_pubkey(leaf_cert.get(), leaf_key.get()));
    EXPECT_EQ(1, X509_set_issuer_name(leaf_cert.get(), X509_get_subject_name(intermediate_cert.get())));
    X509_NAME *leaf_subject = X509_get_subject_name(leaf_cert.get());
    EXPECT_EQ(1, X509_NAME_add_entry_by_txt(leaf_subject, "CN", MBSTRING_ASC,
                                             reinterpret_cast<const unsigned char *>(leaf_cn.data()),
                                             static_cast<int>(leaf_cn.size()), -1, 0));
    EXPECT_TRUE(AddCertificateExtension(leaf_cert.get(), intermediate_cert.get(), NID_basic_constraints,
                                        "critical,CA:FALSE"));
    EXPECT_TRUE(AddCertificateExtension(leaf_cert.get(), intermediate_cert.get(), NID_key_usage,
                                        "critical,digitalSignature"));

    // Embed the server-issued challenge in the Android Key Attestation extension
    // before signing — this is what the mock PKI verifier will extract and check.
    EXPECT_TRUE(AddAndroidAttestationExtension(leaf_cert.get(), challenge));

    EXPECT_GT(X509_sign(leaf_cert.get(), intermediate_key.get(), EVP_sha256()), 0);

    MockChainBundle bundle{};
    if (nullptr == root_cert || nullptr == intermediate_cert || nullptr == leaf_cert)
    {
        return bundle;
    }

    bundle.root_der = EncodeCertificateDer(root_cert.get());
    bundle.chain_der.push_back(EncodeCertificateDer(leaf_cert.get()));
    bundle.chain_der.push_back(EncodeCertificateDer(intermediate_cert.get()));
    bundle.chain_der.push_back(bundle.root_der);
    bundle.leaf_public_key_der = EncodePublicKeyDer(leaf_key.get());
    return bundle;
}

std::string MakeUniqueE2EAttestationKeyName()
{
    static std::size_t counter = 0;
    return "attestation_full_e2e_key_" + std::to_string(++counter);
}

} // namespace

TEST(AttestationApiTest, EmptyChallengeFailsCreate)
{
    if (!mpss::is_algorithm_available(Algorithm::ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const AttestationRequest req{};
    auto key = KeyPair::Create("attestation_empty_challenge", Algorithm::ecdsa_secp256r1_sha256, req);
    EXPECT_EQ(nullptr, key);
    if (nullptr != key)
    {
        key->delete_key();
    }
}

TEST(AttestationApiTest, ApplePolicyDefaultsToAutoSelect)
{
    AttestationRequest request{};
    request.challenge = {std::byte{0x01}};
    EXPECT_EQ(AppleAttestationPolicy::auto_select, request.apple_policy);
}

TEST(AttestationPolicyTest, AutoSelectPrefersAcmeOnlyWhenManagedDevicePathIsAvailable)
{
    EXPECT_EQ(impl::os::AppleAttestationSelection::acme_managed_device,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::auto_select, true, true));
    EXPECT_EQ(impl::os::AppleAttestationSelection::app_attest,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::auto_select, true, false));
    EXPECT_EQ(impl::os::AppleAttestationSelection::app_attest,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::auto_select, false, true));
}

TEST(AttestationPolicyTest, MdmOnlyAndAppAttestOnlySelectionRules)
{
    EXPECT_EQ(impl::os::AppleAttestationSelection::none,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::mdm_only, false, true));
    EXPECT_EQ(impl::os::AppleAttestationSelection::none,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::mdm_only, true, false));
    EXPECT_EQ(impl::os::AppleAttestationSelection::acme_managed_device,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::mdm_only, true, true));
    EXPECT_EQ(impl::os::AppleAttestationSelection::app_attest,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::app_attest_only, false, false));
    EXPECT_EQ(impl::os::AppleAttestationSelection::app_attest,
              impl::os::select_apple_attestation_selection(AppleAttestationPolicy::app_attest_only, true, true));
}

TEST(AttestationE2ETest, FullAttestationWithMockPkiService)
{
    SCOPED_TRACE("Creating attested key and validating evidence through mock PKI.");

    if (!mpss::is_algorithm_available(Algorithm::ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();

    AttestationRequest request{};
    request.challenge = challenge;
    request.requirement = AttestationRequirement::request;

    auto key = KeyPair::Create(MakeUniqueE2EAttestationKeyName(), Algorithm::ecdsa_secp256r1_sha256, request);
    ASSERT_NE(nullptr, key);

    SCOPE_GUARD({
        if (nullptr != key)
        {
            key->delete_key();
        }
    });

    if (!key->supports_attestation())
    {
        GTEST_SKIP() << "Backend does not report attestation support.";
    }

    const auto evidence = key->attestation();
    if (!evidence.has_value())
    {
        GTEST_SKIP() << "Backend did not produce attestation evidence.";
    }

    SCOPED_TRACE(::testing::Message()
                 << "Backend=" << key->backend_name() << ", format=" << AttestationFormatName(evidence->format)
                 << ", statement_bytes=" << evidence->statement.size() << ", cert_chain_len="
                 << evidence->cert_chain.size());

    if (AttestationFormat::none == evidence->format)
    {
        GTEST_SKIP() << "Attestation evidence format is none.";
    }

    if (!evidence->cert_chain.empty())
    {
        pki.set_trusted_root(evidence->format, evidence->cert_chain.back());
    }
    else if (AttestationFormat::apple_app_attest != evidence->format)
    {
        GTEST_SKIP() << "Attestation evidence does not include a certificate chain for this format.";
    }

    std::vector<std::byte> csr_public_key(key->extract_key({}));
    ASSERT_FALSE(csr_public_key.empty());
    ASSERT_EQ(csr_public_key.size(), key->extract_key(csr_public_key));

    const auto result = pki.submit(mock_pki::MockCsr{csr_public_key}, *evidence, evidence->format);
    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
    if (AttestationFormat::apple_app_attest == evidence->format)
    {
        EXPECT_TRUE(result.weaker_assurance);
    }
    else
    {
        EXPECT_FALSE(result.weaker_assurance);
    }
}

TEST(AttestationE2ETest, MockPkiAcceptsTpmVbsAppleAppAppleAcmeAndAndroidEvidence)
{
    const std::vector<AttestationFormat> formats{
        AttestationFormat::windows_tpm,
        AttestationFormat::windows_vbs,
        AttestationFormat::apple_app_attest,
        AttestationFormat::apple_acme_managed_device_attestation,
        AttestationFormat::android_key_attestation,
    };

    for (const AttestationFormat format : formats)
    {
        SCOPED_TRACE(::testing::Message() << "format=" << AttestationFormatName(format));
        mock_pki::MockPkiService pki;
        const auto challenge = pki.issue_challenge();

        AttestationEvidence evidence{};
        evidence.format = format;

        std::vector<std::byte> csr_public_key;

        if (AttestationFormat::android_key_attestation == format)
        {
            // Android: the cert chain IS the evidence; the statement is empty.
            // Build a chain where the leaf cert carries the Android Key Attestation
            // extension (OID 1.3.6.1.4.1.11129.2.1.17) with the challenge embedded in
            // the attestationChallenge field — this is what the mock PKI will verify.
            const auto android_chain = BuildAndroidMockChain("Root", "Intermediate", "Leaf", challenge);
            ASSERT_FALSE(android_chain.root_der.empty());
            pki.set_trusted_root(format, android_chain.root_der);
            evidence.statement = {};
            evidence.cert_chain = android_chain.chain_der;
            csr_public_key = android_chain.leaf_public_key_der;
        }
        else
        {
            const auto chain = BuildMockChain("Root", "Intermediate", "Leaf");
            if (AttestationFormat::apple_app_attest == format)
            {
                evidence.statement = BuildAppleAppAttestStatement(challenge, chain.leaf_public_key_der);
            }
            else
            {
                evidence.statement =
                    BuildStatement(StatementPrefixForFormat(format), challenge, chain.leaf_public_key_der);
            }
            if (UsesCertificateChain(format))
            {
                pki.set_trusted_root(format, chain.root_der);
                evidence.cert_chain = chain.chain_der;
            }
            csr_public_key = chain.leaf_public_key_der;
        }

        const auto result = pki.submit(mock_pki::MockCsr{csr_public_key}, evidence, format);
        EXPECT_TRUE(result.signed_cert);
        EXPECT_FALSE(result.reject_reason.has_value());
        if (AttestationFormat::apple_app_attest == format)
        {
            EXPECT_TRUE(result.weaker_assurance);
        }
        else
        {
            EXPECT_FALSE(result.weaker_assurance);
        }
    }
}

TEST(MockPkiTest, AcceptsAndroidEvidence)
{
    // Android Key Attestation: the cert chain IS the evidence; the statement is empty.
    // Build a chain where the leaf cert carries the Android Key Attestation extension
    // (OID 1.3.6.1.4.1.11129.2.1.17) with the challenge in attestationChallenge,
    // then submit to the mock PKI which must extract and verify the challenge from
    // the extension and accept the submission.
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();

    const auto chain =
        BuildAndroidMockChain("Android Root", "Android Intermediate", "Android Leaf", challenge);
    ASSERT_FALSE(chain.root_der.empty());
    pki.set_trusted_root(AttestationFormat::android_key_attestation, chain.root_der);

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::android_key_attestation;
    evidence.statement = {};  // Android statement is empty; cert chain is the evidence.
    evidence.cert_chain = chain.chain_der;

    const auto result = pki.submit(mock_pki::MockCsr{chain.leaf_public_key_der}, evidence,
                                   AttestationFormat::android_key_attestation);
    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
    EXPECT_FALSE(result.weaker_assurance);
}

TEST(MockPkiTest, RejectsNonceReplay)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const auto chain = BuildMockChain("TPM Root", "TPM Intermediate", "TPM Leaf");
    pki.set_trusted_root(AttestationFormat::windows_tpm, chain.root_der);

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::windows_tpm;
    evidence.statement = BuildStatement("MPSS_WINDOWS_TPM_ATTESTATION_V1", challenge, chain.leaf_public_key_der);
    evidence.cert_chain = chain.chain_der;

    const auto first = pki.submit(mock_pki::MockCsr{chain.leaf_public_key_der}, evidence, AttestationFormat::windows_tpm);
    const auto second = pki.submit(mock_pki::MockCsr{chain.leaf_public_key_der}, evidence, AttestationFormat::windows_tpm);

    EXPECT_TRUE(first.signed_cert);
    ASSERT_TRUE(second.reject_reason.has_value());
    EXPECT_EQ(mock_pki::RejectReason::nonce_replayed, *second.reject_reason);
}

TEST(MockPkiTest, RejectsPublicKeyMismatch)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const auto chain = BuildMockChain("TPM Root", "TPM Intermediate", "TPM Leaf");
    pki.set_trusted_root(AttestationFormat::windows_tpm, chain.root_der);

    const std::vector<std::byte> csr_key{std::byte{0x04}, std::byte{0xAA}, std::byte{0xBB}};

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::windows_tpm;
    evidence.statement = BuildStatement("MPSS_WINDOWS_TPM_ATTESTATION_V1", challenge, chain.leaf_public_key_der);
    evidence.cert_chain = chain.chain_der;

    const auto result = pki.submit(mock_pki::MockCsr{csr_key}, evidence, AttestationFormat::windows_tpm);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(mock_pki::RejectReason::public_key_mismatch, *result.reject_reason);
}

TEST(MockPkiTest, AppleAppAttestIsMarkedAsWeakerAssurance)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const std::vector<std::byte> public_key{std::byte{0x04}, std::byte{0x10}, std::byte{0x11}};

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::apple_app_attest;
    evidence.statement = BuildAppleAppAttestStatement(challenge, public_key);

    const auto result = pki.submit(mock_pki::MockCsr{public_key}, evidence, AttestationFormat::apple_app_attest);
    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
    EXPECT_TRUE(result.weaker_assurance);
}

TEST(MockPkiTest, AcceptsAppleAcmeManagedDeviceEvidence)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const auto chain = BuildMockChain("Apple ACME Root", "Apple ACME Intermediate", "Apple ACME Leaf");
    pki.set_trusted_root(AttestationFormat::apple_acme_managed_device_attestation, chain.root_der);

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::apple_acme_managed_device_attestation;
    evidence.statement = BuildStatement("MPSS_APPLE_ACME_MDA_V1", challenge, chain.leaf_public_key_der);
    evidence.cert_chain = chain.chain_der;

    const auto result = pki.submit(mock_pki::MockCsr{chain.leaf_public_key_der}, evidence,
                                   AttestationFormat::apple_acme_managed_device_attestation);
    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
    EXPECT_FALSE(result.weaker_assurance);
}

TEST(MockPkiTest, RejectsAppleAcmeManagedDeviceEvidenceWithoutCertChain)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const auto chain = BuildMockChain("Apple ACME Root", "Apple ACME Intermediate", "Apple ACME Leaf");
    pki.set_trusted_root(AttestationFormat::apple_acme_managed_device_attestation, chain.root_der);

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::apple_acme_managed_device_attestation;
    evidence.statement = BuildStatement("MPSS_APPLE_ACME_MDA_V1", challenge, chain.leaf_public_key_der);

    const auto result = pki.submit(mock_pki::MockCsr{chain.leaf_public_key_der}, evidence,
                                   AttestationFormat::apple_acme_managed_device_attestation);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(mock_pki::RejectReason::invalid_structure, *result.reject_reason);
}

TEST(MockPkiTest, RejectsWindowsEvidenceSignedByWrongSigner)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();

    const auto windows_chain = BuildMockChain("TPM Root", "TPM Intermediate", "TPM Leaf");
    const auto android_chain = BuildMockChain("Android Root", "Android Intermediate", "Android Leaf");
    pki.set_trusted_root(AttestationFormat::windows_tpm, windows_chain.root_der);

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::windows_tpm;
    evidence.statement = BuildStatement("MPSS_WINDOWS_TPM_ATTESTATION_V1", challenge, android_chain.leaf_public_key_der);
    evidence.cert_chain = android_chain.chain_der;

    const auto result = pki.submit(mock_pki::MockCsr{android_chain.leaf_public_key_der}, evidence,
                                   AttestationFormat::windows_tpm);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(mock_pki::RejectReason::invalid_structure, *result.reject_reason);
}

} // namespace mpss::tests
