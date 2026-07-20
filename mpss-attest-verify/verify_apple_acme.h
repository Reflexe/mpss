// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-attest-verify/attestation_verifier.h"
#include <cstddef>
#include <span>

namespace mpss::attest::apple
{

/**
 * @brief Verify Apple ACME Managed Device Attestation evidence (design §7.5).
 *
 * Chains the leaf-first DER X.509 evidence to a caller-pinned Apple root, checks validity at
 * @c policy.clock(), requires the nonce extension (OID 1.2.840.113635.100.8.11.1) to equal
 * @c SHA-256(expected_nonce), and requires the leaf SPKI to equal @p expected_pubkey. The verifier
 * pins no root itself; an empty root set fails closed.
 *
 * @param[in] evidence        Evidence whose @c format is @c apple_acme_managed_device.
 * @param[in] expected_nonce  The relying-party ACME token; hashed with SHA-256 before comparison.
 * @param[in] expected_pubkey Canonical DER SubjectPublicKeyInfo the leaf must attest.
 * @param[in] policy          Roots, clock, and revocation check.
 * @return A @ref AttestationVerifier::Result echoing @c apple_acme_managed_device.
 */
[[nodiscard]]
AttestationVerifier::Result verify_apple_acme_managed_device(const AttestationEvidence &evidence,
                                                             std::span<const std::byte> expected_nonce,
                                                             std::span<const std::byte> expected_pubkey,
                                                             const AttestationVerifier::Policy &policy);

} // namespace mpss::attest::apple
