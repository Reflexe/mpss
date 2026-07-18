// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/attestation_verifier.h"
#include <span>
#include <utility>

namespace mpss::attest
{

namespace
{

// Stage 1 ships per-format verifier stubs only. Each returns a clean "not implemented"
// result echoing the format, so callers can already distinguish real vs VBS formats and
// Stages 2-4 have a single, obvious insertion point per format.
AttestationVerifier::Result not_implemented(AttestationFormat format)
{
    return AttestationVerifier::Result{/* ok */ false, format, AttestationSecurityLevel::unknown,
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

AttestationVerifier::Result verify_windows_tpm_claim(const AttestationEvidence & /*evidence*/,
                                                     std::span<const std::byte> /*nonce*/,
                                                     std::span<const std::byte> /*pubkey*/,
                                                     const AttestationVerifier::Policy & /*policy*/)
{
    return not_implemented(AttestationFormat::windows_tpm_claim);
}

AttestationVerifier::Result verify_windows_vbs_claim(const AttestationEvidence & /*evidence*/,
                                                     std::span<const std::byte> /*nonce*/,
                                                     std::span<const std::byte> /*pubkey*/,
                                                     const AttestationVerifier::Policy & /*policy*/)
{
    return not_implemented(AttestationFormat::windows_vbs_claim);
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
        return Result{/* ok */ false, AttestationFormat::none, AttestationSecurityLevel::unknown,
                      "no attestation evidence"};
    case AttestationFormat::android_key_attestation:
        return verify_android_key_attestation(evidence, expected_nonce, expected_pubkey, policy_);
    case AttestationFormat::apple_acme_managed_device:
        return verify_apple_acme_managed_device(evidence, expected_nonce, expected_pubkey, policy_);
    case AttestationFormat::windows_tpm_claim:
        return verify_windows_tpm_claim(evidence, expected_nonce, expected_pubkey, policy_);
    case AttestationFormat::windows_vbs_claim:
        return verify_windows_vbs_claim(evidence, expected_nonce, expected_pubkey, policy_);
    }

    return Result{/* ok */ false, evidence.format, AttestationSecurityLevel::unknown, "unknown attestation format"};
}

} // namespace mpss::attest
