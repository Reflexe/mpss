// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss-attest-verify/windows_tpm_claim_verifier.h"
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

// Parse only the documented outer framing of the VBS NCrypt claim blob (Windows SDK ncrypt.h). Reads
// are bounds-checked little-endian, safe on a hostile blob. The TPM claim is verified against the
// published Azure vTPM root in windows_tpm_claim_verifier.cpp.

// NCRYPT_VBS_KEY_ATTESTATION_STATEMENT magic 'VKAS'.
constexpr std::uint32_t vbs_statement_magic = 0x53414B56;
// NCRYPT_VBS_ROOT_ATTESTATION_HEADER magic 'VRCH'.
constexpr std::uint32_t vbs_root_header_magic = 0x48435256;

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

AttestationVerifier::Result reject(AttestationFormat format, std::string reason)
{
    return AttestationVerifier::Result{/* ok */ false, format, std::move(reason)};
}

// nullptr if the payload is not an NCrypt claim (wrong variant alternative for a Windows format).
const NCryptClaim *claim_from(const AttestationEvidence &evidence)
{
    return std::holds_alternative<NCryptClaim>(evidence.payload) ? &std::get<NCryptClaim>(evidence.payload) : nullptr;
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
        return detail::verify_windows_tpm_claim(evidence, expected_nonce, expected_pubkey, policy_);
    case AttestationFormat::windows_vbs_claim:
        return verify_windows_vbs_claim(evidence, expected_nonce, expected_pubkey, policy_);
    }

    return Result{/* ok */ false, evidence.format, "unknown attestation format"};
}

} // namespace mpss::attest
