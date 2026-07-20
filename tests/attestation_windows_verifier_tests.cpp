// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Hardware-independent tests for the Windows TPM / VBS per-format verifiers: they exercise only the
// cross-platform verifier (no NCrypt), so every case is deterministic with zero GTEST_SKIP. The
// hardware-dependent generate -> verify paths live in attestation_windows_e2e_tests.cpp.

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include "tests/attestation_windows_tpm_vector.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <gtest/gtest.h>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

namespace mpss::tests
{

namespace
{

std::vector<std::byte> bytes(std::initializer_list<std::uint8_t> values)
{
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (const std::uint8_t v : values)
    {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

std::vector<std::byte> filled(std::size_t count, std::uint8_t value)
{
    return std::vector<std::byte>(count, static_cast<std::byte>(value));
}

void push_u32_le(std::vector<std::byte> &out, std::uint32_t value)
{
    out.push_back(static_cast<std::byte>(value & 0xFFU));
    out.push_back(static_cast<std::byte>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<std::byte>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<std::byte>((value >> 24U) & 0xFFU));
}

// 'VKAS' / 'VRCH' magics of the VBS claim (Windows SDK ncrypt.h).
constexpr std::uint32_t kVkasMagic = 0x53414B56;
constexpr std::uint32_t kVrchMagic = 0x48435256;

std::vector<std::byte> to_bytes(const unsigned char *data, std::size_t len)
{
    std::vector<std::byte> out(len);
    for (std::size_t i = 0; i < len; ++i)
    {
        out[i] = static_cast<std::byte>(data[i]);
    }
    return out;
}

std::vector<std::byte> vector_bundle()
{
    return to_bytes(tpm_vector::kBundle, tpm_vector::kBundle_len);
}
std::vector<std::byte> vector_nonce()
{
    return to_bytes(tpm_vector::kNonce, tpm_vector::kNonce_len);
}
std::vector<std::byte> vector_pubkey()
{
    return to_bytes(tpm_vector::kExpectedPubkey, tpm_vector::kExpectedPubkey_len);
}
std::vector<std::byte> vector_weak_bundle()
{
    return to_bytes(tpm_vector::kWeakBundle, tpm_vector::kWeakBundle_len);
}
std::vector<std::byte> vector_weak_pubkey()
{
    return to_bytes(tpm_vector::kWeakExpectedPubkey, tpm_vector::kWeakExpectedPubkey_len);
}

// A verification policy pinning the published Azure vTPM root (and ICA) at a fixed clock inside the AK
// certificate validity, so the committed vector verifies identically on every runner and never expires.
mpss::attest::AttestationVerifier::Policy vector_policy(bool include_root = true, bool include_ica = true)
{
    mpss::attest::AttestationVerifier::Policy policy;
    policy.roots = [include_root, include_ica](mpss::AttestationFormat format) {
        std::vector<mpss::attest::TrustAnchor> anchors;
        if (format == mpss::AttestationFormat::windows_tpm_claim)
        {
            if (include_root)
            {
                anchors.push_back(mpss::attest::TrustAnchor{to_bytes(tpm_vector::kRoot, tpm_vector::kRoot_len)});
            }
            if (include_ica)
            {
                anchors.push_back(mpss::attest::TrustAnchor{to_bytes(tpm_vector::kIca, tpm_vector::kIca_len)});
            }
        }
        return anchors;
    };
    policy.clock = []() {
        return std::chrono::system_clock::from_time_t(static_cast<std::time_t>(tpm_vector::kFixedClockUnix));
    };
    return policy;
}

} // namespace

// --- verify_windows_vbs_claim: always refused (format is the signal) ---

// Scenario: an empty VBS claim payload (an NCrypt claim of zero bytes).
// Expected behavior: rejected, format echoed as windows_vbs_claim, reason non-empty.
TEST(WindowsVbsVerifierTest, EmptyBlobRejected)
{
    const mpss::attest::AttestationVerifier verifier;
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_vbs_claim;
    evidence.payload = mpss::NCryptClaim{}; // present, but empty

    const auto result = verifier.verify(evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, mpss::AttestationFormat::windows_vbs_claim);
    EXPECT_NE(result.reason.find("empty"), std::string::npos);
}

// Scenario: a well-formed VBS claim (correct VKAS + VRCH magics).
// Expected behavior: still refused as not externally verifiable (per-machine/per-boot root).
TEST(WindowsVbsVerifierTest, WellFormedClaimRefusedAsNotVerifiable)
{
    const mpss::attest::AttestationVerifier verifier;

    std::vector<std::byte> blob;
    push_u32_le(blob, kVkasMagic); // 'VKAS'
    push_u32_le(blob, 2);          // version
    push_u32_le(blob, 5);          // claim type (VBS_ROOT)
    push_u32_le(blob, kVrchMagic); // 'VRCH'
    blob.resize(64, std::byte{0x00});

    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_vbs_claim;
    evidence.payload = blob;

    const auto result = verifier.verify(evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, mpss::AttestationFormat::windows_vbs_claim);
    EXPECT_NE(result.reason.find("not externally verifiable"), std::string::npos);
}

// Scenario: a non-empty blob that is not a well-formed VBS claim.
// Expected behavior: still refused (the format alone is enough to refuse).
TEST(WindowsVbsVerifierTest, MalformedClaimStillRefused)
{
    const mpss::attest::AttestationVerifier verifier;
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_vbs_claim;
    evidence.payload = bytes({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});

    const auto result = verifier.verify(evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, mpss::AttestationFormat::windows_vbs_claim);
    EXPECT_FALSE(result.reason.empty());
}

// --- verify_windows_tpm_claim: real offline verification of the captured Azure vTPM bundle ---

mpss::AttestationEvidence bundle_evidence(std::vector<std::byte> blob)
{
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = std::move(blob);
    return evidence;
}

// Scenario: the real captured bundle verified against the pinned published Microsoft root, no TPM.
// Expected behavior: ok == true -- the subject key is certified by an Azure vTPM AK chaining to the root.
TEST(WindowsTpmVerifierTest, RealBundleVerifiesOffline)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), vector_nonce(), vector_pubkey());
    EXPECT_TRUE(result.ok) << "reason: " << result.reason;
    EXPECT_EQ(result.format, mpss::AttestationFormat::windows_tpm_claim);
}

// Scenario: an empty TPM claim payload (an NCrypt claim of zero bytes).
// Expected behavior: rejected with a reason mentioning the empty blob; format echoed.
TEST(WindowsTpmVerifierTest, EmptyBlobRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    const auto result = verifier.verify(bundle_evidence({}), vector_nonce(), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, mpss::AttestationFormat::windows_tpm_claim);
    EXPECT_NE(result.reason.find("empty"), std::string::npos);
}

// Scenario: TPM evidence whose payload is not an NCrypt claim (default monostate, or a cert chain).
// Expected behavior: rejected as not carrying an NCrypt claim payload; format echoed.
TEST(WindowsTpmVerifierTest, WrongPayloadAlternativeRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    mpss::AttestationEvidence monostate_evidence;
    monostate_evidence.format = mpss::AttestationFormat::windows_tpm_claim; // payload defaults to std::monostate
    const auto monostate_result = verifier.verify(monostate_evidence, vector_nonce(), vector_pubkey());
    EXPECT_FALSE(monostate_result.ok);
    EXPECT_NE(monostate_result.reason.find("NCrypt claim payload"), std::string::npos);

    mpss::AttestationEvidence certchain_evidence;
    certchain_evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    certchain_evidence.payload = mpss::CertChain{filled(16, 0x30)}; // wrong alternative for a Windows format
    const auto certchain_result = verifier.verify(certchain_evidence, vector_nonce(), vector_pubkey());
    EXPECT_FALSE(certchain_result.ok);
    EXPECT_NE(certchain_result.reason.find("NCrypt claim payload"), std::string::npos);
}

// Scenario: a TPM bundle submitted with no expected nonce.
// Expected behavior: rejected before parsing (nothing to bind freshness to).
TEST(WindowsTpmVerifierTest, MissingExpectedNonceRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), {}, vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("nonce"), std::string::npos);
}

// Scenario: a TPM bundle submitted with no expected public key.
// Expected behavior: rejected (nothing to bind the attested key to).
TEST(WindowsTpmVerifierTest, MissingExpectedPubkeyRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), vector_nonce(), {});
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("public key"), std::string::npos);
}

// Scenario: no pinned published root is configured in the policy.
// Expected behavior: rejected -- a TPM claim can only be trusted against a pinned published root.
TEST(WindowsTpmVerifierTest, MissingPinnedRootRejected)
{
    const mpss::attest::AttestationVerifier verifier; // default policy: roots == nullptr

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), vector_nonce(), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("root"), std::string::npos);
}

// Scenario: a blob whose leading bytes are not the "MTB1" bundle header.
// Expected behavior: rejected as a malformed bundle.
TEST(WindowsTpmVerifierTest, BadMagicRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};
    std::vector<std::byte> blob = vector_bundle();
    blob[0] = std::byte{'X'}; // corrupt the 'M' of "MTB1"

    const auto result = verifier.verify(bundle_evidence(std::move(blob)), vector_nonce(), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("MTB1"), std::string::npos);
}

// Scenario: a byte inside the TPMS_ATTEST certify is flipped after signing.
// Expected behavior: rejected -- the AK signature no longer covers the tampered certify.
TEST(WindowsTpmVerifierTest, TamperedCertifyRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};
    std::vector<std::byte> blob = vector_bundle();
    // 'MTB1'(4) + version(1) + u32 length(4) = 9 bytes precede the first (TPMS_ATTEST) field.
    const std::size_t attest_byte = 9 + 20;
    blob[attest_byte] = static_cast<std::byte>(std::to_integer<std::uint8_t>(blob[attest_byte]) ^ 0xFFU);

    const auto result = verifier.verify(bundle_evidence(std::move(blob)), vector_nonce(), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("signature"), std::string::npos);
}

// Scenario: the bundle is intact but the relying party expects a different nonce.
// Expected behavior: rejected -- freshness cannot be confirmed.
TEST(WindowsTpmVerifierTest, WrongNonceRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), filled(32, 0x55), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("nonce"), std::string::npos);
}

// Scenario: the bundle is intact but the relying party expects a different subject public key.
// Expected behavior: rejected -- the certified key is not the key the caller asked about.
TEST(WindowsTpmVerifierTest, WrongExpectedPubkeyRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), vector_nonce(), filled(91, 0x02));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("subject"), std::string::npos);
}

// Scenario: the ICA is not available (only the root is pinned), so the leaf cannot chain.
// Expected behavior: rejected -- the AK cert does not chain to the pinned root.
TEST(WindowsTpmVerifierTest, MissingIntermediateBreaksChain)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy(/* include_root */ true, /* include_ica */ false)};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), vector_nonce(), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("chain"), std::string::npos);
}

// Scenario: verification replayed at a time outside the AK certificate validity window.
// Expected behavior: rejected -- the chain does not validate at that clock.
TEST(WindowsTpmVerifierTest, ExpiredAtVerificationTimeRejected)
{
    mpss::attest::AttestationVerifier::Policy policy = vector_policy();
    policy.clock = []() {
        return std::chrono::system_clock::from_time_t(static_cast<std::time_t>(1577836800)); // 2020-01-01Z
    };
    const mpss::attest::AttestationVerifier verifier{std::move(policy)};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), vector_nonce(), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("chain"), std::string::npos);
}

// Scenario: the AK certificate serial is reported revoked by the policy.
// Expected behavior: rejected before trusting the certify -- fail closed on revocation.
TEST(WindowsTpmVerifierTest, RevokedSerialRejected)
{
    mpss::attest::AttestationVerifier::Policy policy = vector_policy();
    policy.is_revoked = [](std::span<const std::byte>) { return true; };
    const mpss::attest::AttestationVerifier verifier{std::move(policy)};

    const auto result = verifier.verify(bundle_evidence(vector_bundle()), vector_nonce(), vector_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("revoked"), std::string::npos);
}

// Scenario: a real AK-certified bundle whose subject key is migratable (created without fixedTPM /
// fixedParent). Its AK signature, cert chain, certify magic/type, nonce, and subject name all check out.
// Expected behavior: rejected by the hardware-bound hardening -- an AK must not certify an importable or
// migratable key, or "attested" would not mean "hardware-bound key".
TEST(WindowsTpmVerifierTest, MigratableSubjectKeyRejected)
{
    const mpss::attest::AttestationVerifier verifier{vector_policy()};

    const auto result = verifier.verify(bundle_evidence(vector_weak_bundle()), vector_nonce(), vector_weak_pubkey());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("hardware-bound"), std::string::npos) << "reason: " << result.reason;
}

} // namespace mpss::tests
