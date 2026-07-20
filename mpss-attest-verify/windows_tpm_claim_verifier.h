// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include <span>

namespace mpss::attest::detail
{

/**
 * @brief Offline verifier for the Windows @c windows_tpm_claim bundle (Azure vTPM lane).
 *
 * The evidence payload is an @ref mpss::NCryptClaim carrying an "MTB1" bundle of documented TCG
 * primitives (a nonce-bound @c TPM2_Certify of the subject key + its @c TPMT_SIGNATURE + the subject
 * @c TPMT_PUBLIC) plus the leaf AK certificate. Verification is hardware-free: it chains the AK cert
 * to a pinned published Microsoft root, checks the AK signature over the certify, binds the certified
 * subject key to @p pubkey, and confirms the nonce. Every failure path denies (fail closed).
 */
[[nodiscard]]
AttestationVerifier::Result verify_windows_tpm_claim(const AttestationEvidence &evidence,
                                                     std::span<const std::byte> nonce,
                                                     std::span<const std::byte> pubkey,
                                                     const AttestationVerifier::Policy &policy);

} // namespace mpss::attest::detail
