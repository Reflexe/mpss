// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-attest-verify/attestation_verifier.h"
#include <cstddef>
#include <span>
#include <vector>

namespace mpss::attest
{

/**
 * @brief The pinned, in-repo Google hardware key-attestation root certificates.
 *
 * The published Google roots (from android/keyattestation); the public software-attestation root is
 * deliberately excluded and is rejected if supplied as an anchor.
 */
[[nodiscard]]
std::vector<TrustAnchor> pinned_google_hardware_roots();

namespace detail
{

/**
 * @brief Verifies Android Key Attestation evidence (X.509 chain, ext 1.3.6.1.4.1.11129.2.1.17).
 *
 * Chains the evidence to a pinned Google hardware root (rejecting the software root as an anchor) at
 * the policy clock time, honoring the policy revocation set, then checks the nonce and attested
 * public key against the relying party's expectations. Trust comes from the pinned hardware root, so
 * there is no separate security-level check.
 */
[[nodiscard]]
AttestationVerifier::Result verify_android_key_attestation(const AttestationEvidence &evidence,
                                                           std::span<const std::byte> expected_nonce,
                                                           std::span<const std::byte> expected_pubkey,
                                                           const AttestationVerifier::Policy &policy);

} // namespace detail

} // namespace mpss::attest
