// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Hardware-independent tests for the Windows TPM / VBS per-format verifiers: they exercise only the
// cross-platform verifier (no NCrypt), so every case is deterministic with zero GTEST_SKIP. The
// hardware-dependent generate -> verify paths live in attestation_windows_e2e_tests.cpp.

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
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

// 'KAST' outer magic of the TPM AUTHORITY_AND_SUBJECT claim.
constexpr std::uint32_t kKastMagic = 0x5453414B;
// 'VKAS' / 'VRCH' magics of the VBS claim (Windows SDK ncrypt.h).
constexpr std::uint32_t kVkasMagic = 0x53414B56;
constexpr std::uint32_t kVrchMagic = 0x48435256;

// A synthetic 'KAST'-framed buffer to exercise the verifier's parse/reject logic; it never drives a
// successful verification (the verifier always stops at the AIK->EK->root chain gap), so it is a
// structural fixture, not faked passing evidence. A non-empty embed_nonce is placed after the header
// so the freshness gate passes.
std::vector<std::byte> make_kast(std::uint32_t header_size, std::uint32_t cb1, std::uint32_t cb2, std::uint32_t cb3,
                                 std::span<const std::byte> embed_nonce, std::uint32_t magic = kKastMagic)
{
    std::vector<std::byte> out;
    push_u32_le(out, magic);
    push_u32_le(out, 1); // version
    push_u32_le(out, 2); // reserved / sub-type
    push_u32_le(out, header_size);
    push_u32_le(out, cb1);
    push_u32_le(out, cb2);
    push_u32_le(out, cb3);
    while (out.size() < header_size)
    {
        out.push_back(std::byte{0x00});
    }
    const std::size_t body = static_cast<std::size_t>(cb1) + cb2 + cb3;
    std::vector<std::byte> tail(body, std::byte{0x5A});
    if (!embed_nonce.empty() && embed_nonce.size() <= tail.size())
    {
        std::copy(embed_nonce.begin(), embed_nonce.end(), tail.begin());
    }
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}

mpss::attest::AttestationVerifier::Policy policy_with_tpm_root()
{
    mpss::attest::AttestationVerifier::Policy policy;
    policy.roots = [](mpss::AttestationFormat format) {
        std::vector<mpss::attest::TrustAnchor> anchors;
        if (format == mpss::AttestationFormat::windows_tpm_claim)
        {
            anchors.push_back(mpss::attest::TrustAnchor{filled(64, 0xC0)});
        }
        return anchors;
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

// --- verify_windows_tpm_claim: staged shape / policy / parse rejections ---

// Scenario: an empty TPM claim payload (an NCrypt claim of zero bytes).
// Expected behavior: rejected with a reason mentioning the empty blob; format echoed.
TEST(WindowsTpmVerifierTest, EmptyBlobRejected)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = mpss::NCryptClaim{}; // present, but empty

    const auto result = verifier.verify(evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, mpss::AttestationFormat::windows_tpm_claim);
    EXPECT_NE(result.reason.find("empty"), std::string::npos);
}

// Scenario: TPM evidence whose payload is not an NCrypt claim (default monostate, or a cert chain).
// Expected behavior: rejected as not carrying an NCrypt claim payload; format echoed.
TEST(WindowsTpmVerifierTest, WrongPayloadAlternativeRejected)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};

    mpss::AttestationEvidence monostate_evidence;
    monostate_evidence.format = mpss::AttestationFormat::windows_tpm_claim; // payload defaults to std::monostate
    const auto monostate_result = verifier.verify(monostate_evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(monostate_result.ok);
    EXPECT_EQ(monostate_result.format, mpss::AttestationFormat::windows_tpm_claim);
    EXPECT_NE(monostate_result.reason.find("NCrypt claim payload"), std::string::npos);

    mpss::AttestationEvidence certchain_evidence;
    certchain_evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    certchain_evidence.payload = mpss::CertChain{filled(16, 0x30)}; // wrong alternative for a Windows format
    const auto certchain_result = verifier.verify(certchain_evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(certchain_result.ok);
    EXPECT_NE(certchain_result.reason.find("NCrypt claim payload"), std::string::npos);
}

// Scenario: a TPM claim submitted with no expected nonce.
// Expected behavior: rejected before parsing (nothing to bind freshness to).
TEST(WindowsTpmVerifierTest, MissingExpectedNonceRejected)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = filled(64, 0x00);

    const auto result = verifier.verify(evidence, {}, filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("nonce"), std::string::npos);
}

// Scenario: a TPM claim submitted with no expected public key.
// Expected behavior: rejected (nothing to bind the attested key to).
TEST(WindowsTpmVerifierTest, MissingExpectedPubkeyRejected)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = filled(64, 0x00);

    const auto result = verifier.verify(evidence, filled(32, 0x11), {});
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("public key"), std::string::npos);
}

// Scenario: no pinned TPM manufacturer root is configured in the policy.
// Expected behavior: rejected -- a TPM claim can only be trusted against a pinned manufacturer root.
TEST(WindowsTpmVerifierTest, MissingPinnedRootRejected)
{
    const mpss::attest::AttestationVerifier verifier; // default policy: roots == nullptr
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = filled(64, 0x00);

    const auto result = verifier.verify(evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("root"), std::string::npos);
}

// Scenario: a blob whose first four bytes are not the 'KAST' magic.
// Expected behavior: rejected as not a TPM AUTHORITY_AND_SUBJECT claim.
TEST(WindowsTpmVerifierTest, BadMagicRejected)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = make_kast(28, 8, 8, 8, {}, /* magic */ 0xDEADBEEF);

    const auto result = verifier.verify(evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("KAST"), std::string::npos);
}

// Scenario: a 'KAST' frame whose declared blob lengths do not sum to the total size.
// Expected behavior: rejected as malformed (length fields inconsistent).
TEST(WindowsTpmVerifierTest, InconsistentLengthsRejected)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};
    // header(28) + 8 + 8 + 8 = 52, but craft a buffer of a different size by appending junk.
    std::vector<std::byte> blob = make_kast(28, 8, 8, 8, {});
    blob.push_back(std::byte{0xFF}); // now the totals no longer match

    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = blob;

    const auto result = verifier.verify(evidence, filled(32, 0x11), filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("inconsistent"), std::string::npos);
}

// Scenario: a structurally consistent 'KAST' frame that does not contain the expected nonce.
// Expected behavior: rejected -- freshness cannot be confirmed.
TEST(WindowsTpmVerifierTest, NonceNotBoundRejected)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};
    const std::vector<std::byte> nonce = filled(16, 0x11);
    // Body bytes are 0x5A, never 0x11, so the nonce is absent.
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = make_kast(28, 20, 32, 12, {});

    const auto result = verifier.verify(evidence, nonce, filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.reason.find("nonce not found"), std::string::npos);
}

// Scenario: a structurally consistent, nonce-bound 'KAST' frame reaches the final chain stage.
// Expected behavior: refused with the documented AIK->EK->manufacturer-root gap reason (never ok).
TEST(WindowsTpmVerifierTest, StructurallyValidReachesChainGap)
{
    const mpss::attest::AttestationVerifier verifier{policy_with_tpm_root()};
    const std::vector<std::byte> nonce = filled(16, 0x77);
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_tpm_claim;
    evidence.payload = make_kast(28, 20, 32, 12, nonce); // nonce embedded after the header

    const auto result = verifier.verify(evidence, nonce, filled(65, 0x04));
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, mpss::AttestationFormat::windows_tpm_claim);
    EXPECT_NE(result.reason.find("manufacturer-root"), std::string::npos);
}

} // namespace mpss::tests
