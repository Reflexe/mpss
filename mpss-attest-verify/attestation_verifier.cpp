// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/attestation_verifier.h"
#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace mpss::attest
{

namespace
{

// Per-format stubs; Stages 2-4 fill these in. Each echoes the format so callers still
// distinguish real formats from VBS.
AttestationVerifier::Result not_implemented(AttestationFormat format)
{
    return AttestationVerifier::Result{/* ok */ false, format,
                                       "attestation verification for this format is not implemented in Stage 1"};
}

AttestationVerifier::Result verify_android_key_attestation(const AttestationEvidence & /*evidence*/,
                                                           std::span<const std::byte> /*nonce*/,
                                                           std::span<const std::byte> /*pubkey*/,
                                                           const AttestationVerifier::Policy & /*policy*/)
{
    return not_implemented(AttestationFormat::android_key_attestation);
}

AttestationVerifier::Result verify_apple_acme_managed_device(const AttestationEvidence & /*evidence*/,
                                                             std::span<const std::byte> /*nonce*/,
                                                             std::span<const std::byte> /*pubkey*/,
                                                             const AttestationVerifier::Policy & /*policy*/)
{
    return not_implemented(AttestationFormat::apple_acme_managed_device);
}

// Parse only the documented outer framing of the NCrypt claim blobs: the VBS structure is from the
// Windows SDK ncrypt.h, while the TPM 'KAST' frame is validated by its self-consistent length fields
// (its internals are undocumented). Reads are bounds-checked little-endian, safe on a hostile blob.

// NCRYPT_VBS_KEY_ATTESTATION_STATEMENT magic 'VKAS'.
constexpr std::uint32_t vbs_statement_magic = 0x53414B56;
// NCRYPT_VBS_ROOT_ATTESTATION_HEADER magic 'VRCH'.
constexpr std::uint32_t vbs_root_header_magic = 0x48435256;
// TPM AUTHORITY_AND_SUBJECT claim outer magic 'KAST' (undocumented internals).
constexpr std::uint32_t tpm_claim_magic = 0x5453414B;

std::optional<std::uint32_t> read_u32_le(std::span<const std::byte> data, std::size_t offset)
{
    if (offset > data.size() || data.size() - offset < sizeof(std::uint32_t))
    {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(std::to_integer<std::uint32_t>(data[offset])) |
           (std::to_integer<std::uint32_t>(data[offset + 1]) << 8) |
           (std::to_integer<std::uint32_t>(data[offset + 2]) << 16) |
           (std::to_integer<std::uint32_t>(data[offset + 3]) << 24);
}

bool contains_bytes(std::span<const std::byte> haystack, std::span<const std::byte> needle, std::size_t start)
{
    if (needle.empty() || start > haystack.size() || haystack.size() - start < needle.size())
    {
        return false;
    }
    return std::search(haystack.begin() + static_cast<std::ptrdiff_t>(start), haystack.end(), needle.begin(),
                       needle.end()) != haystack.end();
}

AttestationVerifier::Result reject(AttestationFormat format, std::string reason)
{
    return AttestationVerifier::Result{/* ok */ false, format, std::move(reason)};
}

// nullptr if the payload is not an NCrypt claim (wrong variant alternative for a Windows format).
const NCryptClaim *claim_from(const AttestationEvidence &evidence)
{
    return std::holds_alternative<NCryptClaim>(evidence.payload) ? &std::get<NCryptClaim>(evidence.payload) : nullptr;
}

// The Windows TPM AUTHORITY_AND_SUBJECT claim: externally verifiable in principle (subject -> AIK ->
// EK -> manufacturer root). Staged shape/nonce checks now; the offline chain (Stage 4 below) slots in
// once real captured AIK-enrollment vectors exist (design 7.2 / 8).
AttestationVerifier::Result verify_windows_tpm_claim(const AttestationEvidence &evidence,
                                                     std::span<const std::byte> nonce,
                                                     std::span<const std::byte> pubkey,
                                                     const AttestationVerifier::Policy &policy)
{
    constexpr AttestationFormat format = AttestationFormat::windows_tpm_claim;

    const NCryptClaim *const claim = claim_from(evidence);
    if (nullptr == claim)
    {
        return reject(format, "windows_tpm_claim evidence does not carry an NCrypt claim payload");
    }
    if (claim->empty())
    {
        return reject(format, "windows_tpm_claim evidence has an empty claim blob");
    }
    if (nonce.empty())
    {
        return reject(format, "no expected nonce supplied to verify against");
    }
    if (pubkey.empty())
    {
        return reject(format, "no expected public key supplied to verify against");
    }
    const std::vector<TrustAnchor> anchors = policy.roots ? policy.roots(format) : std::vector<TrustAnchor>{};
    if (anchors.empty())
    {
        return reject(format, "no pinned TPM manufacturer root configured (cannot anchor AIK -> EK chain)");
    }

    // 'KAST' frame (little-endian ULONGs): magic | version | reserved | headerSize | cb1 | cb2 | cb3 | blobs.
    const std::span<const std::byte> blob{*claim};
    const std::optional<std::uint32_t> magic = read_u32_le(blob, 0);
    if (!magic || *magic != tpm_claim_magic)
    {
        return reject(format, "not a TPM AUTHORITY_AND_SUBJECT claim (bad KAST magic)");
    }
    const std::optional<std::uint32_t> header_size = read_u32_le(blob, 12);
    const std::optional<std::uint32_t> cb1 = read_u32_le(blob, 16);
    const std::optional<std::uint32_t> cb2 = read_u32_le(blob, 20);
    const std::optional<std::uint32_t> cb3 = read_u32_le(blob, 24);
    if (!header_size || !cb1 || !cb2 || !cb3)
    {
        return reject(format, "malformed KAST claim (truncated header)");
    }
    constexpr std::uint32_t min_header_size = 28; // 7 ULONGs
    const std::uint64_t expected_total = static_cast<std::uint64_t>(*header_size) + *cb1 + *cb2 + *cb3;
    if (*header_size < min_header_size || expected_total != blob.size())
    {
        return reject(format, "malformed KAST claim (length fields inconsistent with blob size)");
    }

    // Nonce presence is only a structural freshness gate; it becomes cryptographic once the Stage 4
    // signature over this region is verified.
    if (!contains_bytes(blob, nonce, *header_size))
    {
        return reject(format, "attestation nonce not found in TPM claim (freshness cannot be confirmed)");
    }

    // Stage 4 gap: a self-issued NCryptCreateClaim carries no AIK/EK chain (that needs a separate AIK
    // enrolment: TPM2_ActivateCredential + an attestation CA) and the 'KAST' crypto layout is
    // undocumented, so we refuse rather than fake a provenance decision (design 7.2 / 8).
    return reject(format, "TPM claim is structurally valid and nonce-bound, but offline AIK -> EK -> "
                          "manufacturer-root verification requires a captured AIK-enrollment vector that a "
                          "self-issued claim does not carry; refusing to assert hardware provenance");
}

// The Windows VBS / Key Guard claim is never externally verifiable: its IDKS root is per-machine and
// per-boot, chaining to no published root. The parse is diagnostic only; the format is always refused.
AttestationVerifier::Result verify_windows_vbs_claim(const AttestationEvidence &evidence,
                                                     std::span<const std::byte> /*nonce*/,
                                                     std::span<const std::byte> /*pubkey*/,
                                                     const AttestationVerifier::Policy & /*policy*/)
{
    constexpr AttestationFormat format = AttestationFormat::windows_vbs_claim;

    const NCryptClaim *const claim = claim_from(evidence);
    if (nullptr == claim)
    {
        return reject(format, "windows_vbs_claim evidence does not carry an NCrypt claim payload");
    }
    if (claim->empty())
    {
        return reject(format, "windows_vbs_claim evidence has an empty claim blob");
    }

    // 'VKAS' statement wrapping a 'VRCH' root header (ncrypt.h); refused either way.
    const std::span<const std::byte> blob{*claim};
    const std::optional<std::uint32_t> statement_magic = read_u32_le(blob, 0);
    const std::optional<std::uint32_t> root_magic = read_u32_le(blob, 12);
    const bool well_formed = statement_magic && *statement_magic == vbs_statement_magic && root_magic &&
                             *root_magic == vbs_root_header_magic;

    return reject(format, well_formed ? "windows_vbs_claim is not externally verifiable: its VBS root (IDKS) is "
                                        "per-machine/per-boot and cannot chain to a published root; a relying party "
                                        "requiring real attestation must refuse this format"
                                      : "windows_vbs_claim is not externally verifiable and the blob is not a "
                                        "well-formed VBS claim (bad VKAS/VRCH magic); refused");
}

} // namespace

AttestationVerifier::AttestationVerifier(Policy policy) : policy_{std::move(policy)}
{
}

AttestationVerifier::Result AttestationVerifier::verify(const AttestationEvidence &evidence,
                                                        std::span<const std::byte> expected_nonce,
                                                        std::span<const std::byte> expected_pubkey) const
{
    switch (evidence.format)
    {
    case AttestationFormat::none:
        return Result{/* ok */ false, AttestationFormat::none, "no attestation evidence"};
    case AttestationFormat::android_key_attestation:
        return verify_android_key_attestation(evidence, expected_nonce, expected_pubkey, policy_);
    case AttestationFormat::apple_acme_managed_device:
        return verify_apple_acme_managed_device(evidence, expected_nonce, expected_pubkey, policy_);
    case AttestationFormat::windows_tpm_claim:
        return verify_windows_tpm_claim(evidence, expected_nonce, expected_pubkey, policy_);
    case AttestationFormat::windows_vbs_claim:
        return verify_windows_vbs_claim(evidence, expected_nonce, expected_pubkey, policy_);
    }

    return Result{/* ok */ false, evidence.format, "unknown attestation format"};
}

} // namespace mpss::attest
