// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/android_key_attestation.h"
#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include "tests/mock_pki/android_fixtures.h"
#include "tests/mock_pki/mock_pki.h"
#include "tests/mock_pki/test_ca.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <span>
#include <string>
#include <vector>

namespace mpss::tests
{

namespace
{

using mpss::attest::AttestationVerifier;
using mpss::attest::TrustAnchor;
using mpss::tests::mock_pki::AndroidCertOptions;
using mpss::tests::mock_pki::android_one_year_seconds;
using mpss::tests::mock_pki::cert_serial_bytes;
using mpss::tests::mock_pki::generate_ec_key;
using mpss::tests::mock_pki::make_android_cert;
using mpss::tests::mock_pki::make_key_description;
using mpss::tests::mock_pki::TestCert;
using mpss::tests::mock_pki::TestKey;
using mpss::tests::mock_pki::TestSecurityLevel;

// The published Google Android Keystore *software* attestation root (never a valid anchor).
constexpr const char *google_software_root_pem = R"(-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
-----END CERTIFICATE-----)";

std::vector<std::byte> make_bytes(std::size_t count, std::byte value)
{
    return std::vector<std::byte>(count, value);
}

std::vector<std::byte> pem_to_der(const char *pem)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{BIO_new_mem_buf(pem, -1), BIO_free};
    std::unique_ptr<X509, decltype(&X509_free)> cert{
        PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free};
    if (nullptr == cert)
    {
        return {};
    }
    const int size = i2d_X509(cert.get(), nullptr);
    std::vector<std::byte> der(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(der.data());
    i2d_X509(cert.get(), &cursor);
    return der;
}

// A fabricated, structurally-real Android attestation chain: a test "Google hardware root" ->
// intermediate -> attestation leaf (carrying a KeyDescription with a known challenge + level).
struct FakeChain
{
    TestKey root_key{generate_ec_key()};
    TestKey intermediate_key{generate_ec_key()};
    TestKey leaf_key{generate_ec_key()};
    TestCert root;
    TestCert intermediate;
    TestCert leaf;

    [[nodiscard]]
    std::vector<std::vector<std::byte>> chain() const
    {
        return {leaf.der, intermediate.der, root.der};
    }
};

// Builds a valid three-cert chain; the leaf carries the attestation extension.
FakeChain build_chain(std::span<const std::byte> leaf_challenge, TestSecurityLevel level, long leaf_serial = 3,
                      long leaf_not_before = -3600, long leaf_not_after = android_one_year_seconds)
{
    FakeChain fc;
    fc.root = make_android_cert(fc.root_key, fc.root_key, nullptr,
                                {.common_name = "Test Google HW Attestation Root",
                                 .serial = 1,
                                 .is_ca = true,
                                 .not_before_offset_seconds = -3600});
    fc.intermediate = make_android_cert(fc.intermediate_key, fc.root_key, &fc.root,
                                        {.common_name = "Test Attestation Intermediate",
                                         .serial = 2,
                                         .is_ca = true,
                                         .not_before_offset_seconds = -3600});
    fc.leaf = make_android_cert(fc.leaf_key, fc.intermediate_key, &fc.intermediate,
                                {.common_name = "Android Keystore Key",
                                 .serial = leaf_serial,
                                 .is_ca = false,
                                 .not_before_offset_seconds = leaf_not_before,
                                 .not_after_offset_seconds = leaf_not_after,
                                 .key_description = make_key_description(leaf_challenge, level)});
    return fc;
}

AttestationVerifier::Policy make_policy(
    const TestCert &anchor, std::function<bool(std::span<const std::byte>)> is_revoked = nullptr,
    std::chrono::system_clock::time_point clock = std::chrono::system_clock::now())
{
    AttestationVerifier::Policy policy;
    policy.roots = [der = anchor.der](AttestationFormat format) {
        std::vector<TrustAnchor> anchors;
        if (AttestationFormat::android_key_attestation == format)
        {
            anchors.push_back(TrustAnchor{der});
        }
        return anchors;
    };
    policy.clock = [clock] { return clock; };
    if (is_revoked)
    {
        policy.is_revoked = std::move(is_revoked);
    }
    else
    {
        policy.is_revoked = [](std::span<const std::byte>) { return false; };
    }
    return policy;
}

AttestationEvidence make_evidence(const FakeChain &fc)
{
    AttestationEvidence evidence;
    evidence.format = AttestationFormat::android_key_attestation;
    evidence.payload = fc.chain();
    return evidence;
}

} // namespace

// Scenario: a valid TEE-level Android chain whose challenge and key match expectations (TA-2).
// Scenario: a valid TEE-level Android chain whose challenge and key match expectations (TA-2).
// Expected behavior: verification succeeds and echoes the android_key_attestation format.
TEST(AndroidKeyAttestationTest, ValidTeeChainVerifies)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x5A});
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::trusted_environment);
    ASSERT_TRUE(fc.leaf.valid());

    const AttestationVerifier verifier{make_policy(fc.root)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, fc.leaf_key.spki_der);

    EXPECT_TRUE(result.ok) << result.reason;
    EXPECT_EQ(result.format, AttestationFormat::android_key_attestation);
}

// Scenario: a valid StrongBox-provisioned chain (its KeyDescription encodes StrongBox) (UC-A1, TA-3).
// Expected behavior: verification succeeds; trust derives from chaining to the pinned root.
TEST(AndroidKeyAttestationTest, ValidStrongBoxChainVerifies)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x11});
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::strongbox);

    const AttestationVerifier verifier{make_policy(fc.root)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, fc.leaf_key.spki_der);

    EXPECT_TRUE(result.ok) << result.reason;
    EXPECT_EQ(result.format, AttestationFormat::android_key_attestation);
}

// Scenario: the evidence binds a different challenge than the relying party expects (TA-4).
// Expected behavior: verification fails (the nonce is not bound in the evidence).
TEST(AndroidKeyAttestationTest, WrongChallengeRejected)
{
    const std::vector<std::byte> bound = make_bytes(32, std::byte{0xAA});
    const std::vector<std::byte> expected = make_bytes(32, std::byte{0xBB});
    const FakeChain fc = build_chain(bound, TestSecurityLevel::trusted_environment);

    const AttestationVerifier verifier{make_policy(fc.root)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), expected, fc.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("challenge"), std::string::npos);
}

// Scenario: the chain terminates in a root other than the pinned hardware root, e.g. a
// software-backed (emulator) root (TA-5).
// Expected behavior: path validation fails because the chain does not reach the pinned anchor.
TEST(AndroidKeyAttestationTest, ChainNotReachingPinnedRootRejected)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x42});
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::trusted_environment);

    // Pin a *different* root than the one the chain chains to.
    const TestKey other_root_key = generate_ec_key();
    const TestCert other_root = make_android_cert(
        other_root_key, other_root_key, nullptr,
        {.common_name = "Unrelated Root", .serial = 1, .is_ca = true, .not_before_offset_seconds = -3600});

    const AttestationVerifier verifier{make_policy(other_root)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, fc.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
}

// Scenario: a certificate in an otherwise valid chain is on the revocation list (TA-6).
// Expected behavior: verification fails because a chain certificate is revoked.
TEST(AndroidKeyAttestationTest, RevokedSerialRejected)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x33});
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::trusted_environment, /* leaf_serial */ 77);

    const std::vector<std::byte> revoked = cert_serial_bytes(fc.leaf);
    ASSERT_FALSE(revoked.empty());
    auto is_revoked = [revoked](std::span<const std::byte> serial) {
        return serial.size() == revoked.size()
               && std::equal(serial.begin(), serial.end(), revoked.begin());
    };

    const AttestationVerifier verifier{make_policy(fc.root, is_revoked)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, fc.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("revoked"), std::string::npos);
}

// Scenario: an RKP leaf whose validity window ended before the (injected) verification time (TA-7).
// Expected behavior: path validation fails because a certificate has expired.
TEST(AndroidKeyAttestationTest, ExpiredCertRejected)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x66});
    // Leaf valid two years ago .. one year ago; verified at "now".
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::trusted_environment, /* leaf_serial */ 3,
                                     /* leaf_not_before */ -2 * android_one_year_seconds,
                                     /* leaf_not_after */ -android_one_year_seconds);

    const AttestationVerifier verifier{make_policy(fc.root)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, fc.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
}

// Scenario: a forged leaf carrying an injected extension is prepended below a genuine attestation
// certificate whose extension sits nearer the root (TA-8).
// Expected behavior: only the nearest-root extension is trusted, so the forged (expected) challenge
// is ignored and verification fails on the genuine certificate's challenge.
TEST(AndroidKeyAttestationTest, ExtensionInjectionTrustsOnlyNearestRoot)
{
    const std::vector<std::byte> genuine_challenge = make_bytes(32, std::byte{0xAA});
    const std::vector<std::byte> attacker_challenge = make_bytes(32, std::byte{0xBB});

    const TestKey root_key = generate_ec_key();
    const TestKey intermediate_key = generate_ec_key();
    const TestKey hardware_key = generate_ec_key(); // genuine attested key
    const TestKey attacker_key = generate_ec_key();

    const TestCert root = make_android_cert(
        root_key, root_key, nullptr,
        {.common_name = "Test Google HW Attestation Root", .serial = 1, .is_ca = true, .not_before_offset_seconds = -3600});
    const TestCert intermediate = make_android_cert(intermediate_key, root_key, &root,
                                                    {.common_name = "Test Attestation Intermediate",
                                                     .serial = 2,
                                                     .is_ca = true,
                                                     .not_before_offset_seconds = -3600});
    // Genuine attestation certificate: real challenge + real key, made a CA so a cert can (illegitimately)
    // be issued below it.
    const TestCert genuine = make_android_cert(
        hardware_key, intermediate_key, &intermediate,
        {.common_name = "Android Keystore Key",
         .serial = 3,
         .is_ca = true,
         .not_before_offset_seconds = -3600,
         .key_description = make_key_description(genuine_challenge, TestSecurityLevel::trusted_environment)});
    // Forged leaf: attacker injects the *expected* challenge and their own key, signed by the genuine key.
    const TestCert forged = make_android_cert(
        attacker_key, hardware_key, &genuine,
        {.common_name = "Forged Injected Leaf",
         .serial = 4,
         .is_ca = false,
         .not_before_offset_seconds = -3600,
         .key_description = make_key_description(attacker_challenge, TestSecurityLevel::trusted_environment)});
    ASSERT_TRUE(forged.valid());

    AttestationEvidence evidence;
    evidence.format = AttestationFormat::android_key_attestation;
    evidence.payload = mpss::CertChain{forged.der, genuine.der, intermediate.der, root.der};

    // The relying party expects the attacker's injected values.
    const AttestationVerifier verifier{make_policy(root)};
    const AttestationVerifier::Result result =
        verifier.verify(evidence, attacker_challenge, attacker_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("challenge"), std::string::npos) << result.reason;
}

// Scenario: the public Google software-attestation root is supplied as a trust anchor.
// Expected behavior: verification fails; the software root is refused as an anchor.
TEST(AndroidKeyAttestationTest, SoftwareRootAsAnchorRejected)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x44});
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::trusted_environment);

    const std::vector<std::byte> software_root_der = pem_to_der(google_software_root_pem);
    ASSERT_FALSE(software_root_der.empty());

    AttestationVerifier::Policy policy;
    policy.roots = [software_root_der](AttestationFormat) {
        return std::vector<TrustAnchor>{TrustAnchor{software_root_der}};
    };
    policy.clock = [] { return std::chrono::system_clock::now(); };
    policy.is_revoked = [](std::span<const std::byte>) { return false; };

    const AttestationVerifier verifier{std::move(policy)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, fc.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("software"), std::string::npos);
}

// Scenario: a valid chain whose attested key differs from the key the relying party expects.
// Expected behavior: verification fails on the public-key binding check.
TEST(AndroidKeyAttestationTest, AttestedKeyMismatchRejected)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x55});
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::trusted_environment);
    const TestKey unrelated = generate_ec_key();

    const AttestationVerifier verifier{make_policy(fc.root)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, unrelated.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("key"), std::string::npos);
}

// Scenario: a validly-chained set of certificates with no attestation extension anywhere.
// Expected behavior: verification fails because no KeyDescription is present.
TEST(AndroidKeyAttestationTest, MissingExtensionRejected)
{
    const std::vector<std::byte> nonce = make_bytes(32, std::byte{0x77});
    FakeChain fc;
    fc.root = make_android_cert(fc.root_key, fc.root_key, nullptr,
                                {.common_name = "Test Google HW Attestation Root",
                                 .serial = 1,
                                 .is_ca = true,
                                 .not_before_offset_seconds = -3600});
    fc.intermediate = make_android_cert(fc.intermediate_key, fc.root_key, &fc.root,
                                        {.common_name = "Test Attestation Intermediate",
                                         .serial = 2,
                                         .is_ca = true,
                                         .not_before_offset_seconds = -3600});
    // Leaf without a KeyDescription extension.
    fc.leaf = make_android_cert(fc.leaf_key, fc.intermediate_key, &fc.intermediate,
                                {.common_name = "Android Keystore Key",
                                 .serial = 3,
                                 .is_ca = false,
                                 .not_before_offset_seconds = -3600});
    ASSERT_TRUE(fc.leaf.valid());

    const AttestationVerifier verifier{make_policy(fc.root)};
    const AttestationVerifier::Result result = verifier.verify(make_evidence(fc), nonce, fc.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("extension"), std::string::npos);
}

// Scenario: the in-repo pinned Google hardware roots are loaded.
// Expected behavior: exactly two self-signed roots are returned and parse as X.509 certificates.
TEST(AndroidKeyAttestationTest, PinnedHardwareRootsAreValid)
{
    const std::vector<TrustAnchor> roots = mpss::attest::pinned_google_hardware_roots();
    ASSERT_EQ(roots.size(), 2u);

    for (const TrustAnchor &anchor : roots)
    {
        const auto *cursor = reinterpret_cast<const unsigned char *>(anchor.der.data());
        std::unique_ptr<X509, decltype(&X509_free)> cert{
            d2i_X509(nullptr, &cursor, static_cast<long>(anchor.der.size())), X509_free};
        ASSERT_NE(cert, nullptr);
        // Roots are self-issued.
        EXPECT_EQ(0, X509_NAME_cmp(X509_get_subject_name(cert.get()), X509_get_issuer_name(cert.get())));
    }
}

// Scenario: a fresh nonce and a valid TEE chain flow end-to-end through the reduced mock PKI.
// Expected behavior: the mock PKI consults the shared verifier, which succeeds, and the CSR is signed.
TEST(AndroidKeyAttestationTest, EndToEndThroughMockPkiSucceeds)
{
    using mpss::tests::mock_pki::MockCsr;
    using mpss::tests::mock_pki::MockPkiService;

    MockPkiService pki;
    // Build the chain first so the leaf's challenge equals the nonce the PKI issued.
    const std::vector<std::byte> nonce = pki.issue_challenge();
    const FakeChain fc = build_chain(nonce, TestSecurityLevel::trusted_environment);
    pki.set_trusted_root(AttestationFormat::android_key_attestation, TrustAnchor{fc.root.der});

    const MockCsr csr{fc.leaf_key.spki_der};
    const auto result =
        pki.submit(csr, make_evidence(fc), nonce, AttestationFormat::android_key_attestation);

    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
    EXPECT_TRUE(result.verifier_result.ok) << result.verifier_result.reason;
    EXPECT_EQ(result.verifier_result.format, AttestationFormat::android_key_attestation);
}

} // namespace mpss::tests
