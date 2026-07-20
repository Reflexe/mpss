// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include "tests/mock_pki/mock_pki.h"
#include "tests/mock_pki/test_ca.h"
#include <chrono>
#include <cstddef>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace mpss::tests
{

namespace
{

using mpss::attest::AttestationVerifier;
using mpss::attest::TrustAnchor;
using mpss::tests::mock_pki::AttestationLeafSpec;
using mpss::tests::mock_pki::create_attestation_leaf;
using mpss::tests::mock_pki::create_root;
using mpss::tests::mock_pki::generate_ec_key;
using mpss::tests::mock_pki::TestCert;
using mpss::tests::mock_pki::TestKey;

// Apple ACME challenge-nonce OID (design §7.5).
constexpr const char *apple_nonce_oid = "1.2.840.113635.100.8.11.1";

std::vector<std::byte> make_bytes(std::size_t count, std::byte value)
{
    return std::vector<std::byte>(count, value);
}

std::vector<std::byte> sha256(std::span<const std::byte> in)
{
    std::vector<std::byte> out(32);
    unsigned int len = 0;
    EVP_Digest(in.data(), in.size(), reinterpret_cast<unsigned char *>(out.data()), &len, EVP_sha256(), nullptr);
    return out;
}

// A structurally-real Apple ACME setup: test root, leaf bound to leaf_key with the nonce OID, and evidence.
struct AcmeSetup
{
    TestKey root_key;
    TestKey leaf_key;
    TestCert root;
    TestCert leaf;
    std::vector<std::byte> challenge; // raw ACME token / relying-party nonce
    AttestationEvidence evidence;
};

// `embedded_nonce_digest` goes under the nonce OID (empty => no extension); validity is offsets from now.
AcmeSetup make_setup(std::span<const std::byte> embedded_nonce_digest, std::chrono::seconds not_before_from_now,
                     std::chrono::seconds not_after_from_now)
{
    AcmeSetup s;
    s.root_key = generate_ec_key();
    s.leaf_key = generate_ec_key();
    // A long-lived root so leaf-expiry tests are never masked by root expiry.
    s.root = create_root(s.root_key, "Test Apple Enterprise Attestation Root", std::chrono::hours{24 * 365 * 10});

    AttestationLeafSpec spec;
    spec.common_name = "Test Apple ACME Device Leaf";
    spec.extension_oid = embedded_nonce_digest.empty() ? std::string_view{} : std::string_view{apple_nonce_oid};
    spec.extension_value = embedded_nonce_digest;
    spec.not_before_from_now = not_before_from_now;
    spec.not_after_from_now = not_after_from_now;
    s.leaf = create_attestation_leaf(s.leaf_key, s.root_key, s.root, spec);

    s.evidence.format = AttestationFormat::apple_acme_managed_device;
    s.evidence.payload = mpss::CertChain{s.leaf.der};
    return s;
}

// A standard valid setup: leaf carries SHA-256(challenge) and is valid now.
AcmeSetup make_valid_setup(const std::vector<std::byte> &challenge)
{
    AcmeSetup s = make_setup(sha256(challenge), std::chrono::seconds{-60}, std::chrono::hours{24 * 365});
    s.challenge = challenge;
    return s;
}

AttestationVerifier::Policy make_policy(std::vector<std::byte> root_der,
                                        std::chrono::system_clock::time_point clock = std::chrono::system_clock::now())
{
    AttestationVerifier::Policy policy;
    policy.roots = [root_der = std::move(root_der)](AttestationFormat format) {
        std::vector<TrustAnchor> anchors;
        if (AttestationFormat::apple_acme_managed_device == format)
        {
            anchors.push_back(TrustAnchor{root_der});
        }
        return anchors;
    };
    policy.clock = [clock] { return clock; };
    policy.is_revoked = [](std::span<const std::byte>) { return false; };
    return policy;
}

} // namespace

// --- TM-1: valid ACME chain passes ---

// Scenario: a structurally-real ACME chain (test Apple root -> leaf with the nonce OID + known key)
//           whose leaf is valid now, verified against the pinned test root.
// Expected behavior: verification succeeds and echoes the apple_acme_managed_device format.
TEST(AppleAcmeVerifierTest, ValidChainPasses)
{
    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    const AcmeSetup s = make_valid_setup(challenge);
    ASSERT_TRUE(s.root.valid());
    ASSERT_TRUE(s.leaf.valid());

    const AttestationVerifier verifier{make_policy(s.root.der)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, challenge, s.leaf_key.spki_der);

    EXPECT_TRUE(result.ok) << result.reason;
    EXPECT_EQ(result.format, AttestationFormat::apple_acme_managed_device);
}

// --- TM-2: wrong nonce value in the OID rejects ---

// Scenario: the leaf embeds SHA-256 of a DIFFERENT challenge than the one the relying party expects.
// Expected behavior: verification fails with a nonce-related reason.
TEST(AppleAcmeVerifierTest, WrongNonceRejected)
{
    const std::vector<std::byte> expected_challenge = make_bytes(32, std::byte{0xA1});
    const std::vector<std::byte> other_challenge = make_bytes(32, std::byte{0xB2});

    // Leaf carries SHA-256(other_challenge) but we verify against expected_challenge.
    AcmeSetup s = make_setup(sha256(other_challenge), std::chrono::seconds{-60}, std::chrono::hours{24 * 365});
    ASSERT_TRUE(s.leaf.valid());

    const AttestationVerifier verifier{make_policy(s.root.der)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, expected_challenge, s.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, AttestationFormat::apple_acme_managed_device);
    EXPECT_NE(result.reason.find("nonce"), std::string::npos);
}

// --- TM-3: chain that does not root in the pinned Apple root rejects ---

// Scenario: a valid leaf signed by root A, but the policy pins an unrelated root B (non-Apple root).
// Expected behavior: chain verification fails; the evidence is rejected.
TEST(AppleAcmeVerifierTest, NonAppleRootRejected)
{
    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    const AcmeSetup s = make_valid_setup(challenge);
    ASSERT_TRUE(s.leaf.valid());

    // An unrelated root that did not sign the leaf.
    const TestKey other_root_key = generate_ec_key();
    const TestCert other_root = create_root(other_root_key, "Some Other Root");
    ASSERT_TRUE(other_root.valid());

    const AttestationVerifier verifier{make_policy(other_root.der)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, challenge, s.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("chain"), std::string::npos);
}

// --- TM-4: expired leaf rejects ---

// Scenario: the leaf's validity window is entirely in the past (already expired), verified at now.
// Expected behavior: chain verification fails on expiry; the evidence is rejected.
TEST(AppleAcmeVerifierTest, ExpiredLeafRejected)
{
    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    // notBefore = -2y, notAfter = -1y  => expired relative to now.
    AcmeSetup s = make_setup(sha256(challenge), std::chrono::hours{-24 * 365 * 2}, std::chrono::hours{-24 * 365});
    ASSERT_TRUE(s.leaf.valid());

    const AttestationVerifier verifier{make_policy(s.root.der)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, challenge, s.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("chain"), std::string::npos);
}

// --- Additional negative cases ---

// Scenario: the leaf lacks the ACME nonce extension entirely.
// Expected behavior: verification fails because the nonce extension is not found.
TEST(AppleAcmeVerifierTest, MissingNonceExtensionRejected)
{
    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    AcmeSetup s = make_setup(/* no extension */ {}, std::chrono::seconds{-60}, std::chrono::hours{24 * 365});
    ASSERT_TRUE(s.leaf.valid());

    const AttestationVerifier verifier{make_policy(s.root.der)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, challenge, s.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("nonce"), std::string::npos);
}

// Scenario: the attested leaf key differs from the public key the relying party expects.
// Expected behavior: verification fails on the key-binding check.
TEST(AppleAcmeVerifierTest, KeyBindingMismatchRejected)
{
    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    const AcmeSetup s = make_valid_setup(challenge);
    ASSERT_TRUE(s.leaf.valid());

    // A different key than the one bound in the leaf.
    const TestKey unrelated_key = generate_ec_key();
    ASSERT_TRUE(unrelated_key.valid());

    const AttestationVerifier verifier{make_policy(s.root.der)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, challenge, unrelated_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("key"), std::string::npos);
}

// Scenario: no trust anchor is pinned for the Apple ACME format.
// Expected behavior: verification fails rather than trusting an unpinned chain.
TEST(AppleAcmeVerifierTest, NoPinnedRootRejected)
{
    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    const AcmeSetup s = make_valid_setup(challenge);
    ASSERT_TRUE(s.leaf.valid());

    AttestationVerifier::Policy policy;
    policy.roots = [](AttestationFormat) { return std::vector<TrustAnchor>{}; };
    policy.clock = [] { return std::chrono::system_clock::now(); };
    policy.is_revoked = [](std::span<const std::byte>) { return false; };

    const AttestationVerifier verifier{std::move(policy)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, challenge, s.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("root"), std::string::npos);
}

// Scenario: evidence carrying an empty certificate chain.
// Expected behavior: verification fails without dereferencing a missing leaf.
TEST(AppleAcmeVerifierTest, EmptyChainRejected)
{
    AttestationEvidence evidence;
    evidence.format = AttestationFormat::apple_acme_managed_device;
    evidence.payload = mpss::CertChain{}; // empty chain

    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    const std::vector<std::byte> pubkey = make_bytes(64, std::byte{0x01});

    const AttestationVerifier verifier{make_policy(make_bytes(4, std::byte{0x00}))};
    const AttestationVerifier::Result result = verifier.verify(evidence, challenge, pubkey);

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, AttestationFormat::apple_acme_managed_device);
}

// --- End-to-end through the reduced mock PKI ---

// Scenario: a fresh challenge and a valid Apple ACME chain flow through the mock PKI, which pins the
//           test root and delegates verification to the shared verifier.
// Expected behavior: nonce bookkeeping passes, the verifier accepts, and the CSR is signed.
TEST(AppleAcmeVerifierTest, MockPkiSignsValidAcmeEvidence)
{
    using mpss::tests::mock_pki::MockCsr;
    using mpss::tests::mock_pki::MockPkiService;

    MockPkiService pki;
    const std::vector<std::byte> challenge = pki.issue_challenge();
    const AcmeSetup s = make_valid_setup(challenge);
    ASSERT_TRUE(s.leaf.valid());

    pki.set_trusted_root(AttestationFormat::apple_acme_managed_device, TrustAnchor{s.root.der});

    const MockCsr csr{s.leaf_key.spki_der};
    const auto result = pki.submit(csr, s.evidence, challenge, AttestationFormat::apple_acme_managed_device);

    EXPECT_TRUE(result.signed_cert) << (result.verifier_result.reason);
    EXPECT_FALSE(result.reject_reason.has_value());
    EXPECT_TRUE(result.verifier_result.ok);
}

// --- Tampered leaf rejected ---

// Scenario: a byte in an otherwise-valid leaf certificate's DER is flipped after issuance.
// Expected behavior: chain verification fails (parse or signature) and the evidence is rejected.
TEST(AppleAcmeVerifierTest, TamperedLeafRejected)
{
    const std::vector<std::byte> challenge = make_bytes(32, std::byte{0xA1});
    AcmeSetup s = make_valid_setup(challenge);
    ASSERT_TRUE(s.leaf.valid());

    auto &chain = std::get<mpss::CertChain>(s.evidence.payload);
    ASSERT_FALSE(chain.empty());
    ASSERT_FALSE(chain.front().empty());
    chain.front()[chain.front().size() / 2] ^= std::byte{0xFF};

    const AttestationVerifier verifier{make_policy(s.root.der)};
    const AttestationVerifier::Result result = verifier.verify(s.evidence, challenge, s.leaf_key.spki_der);

    EXPECT_FALSE(result.ok);
}

} // namespace mpss::tests
