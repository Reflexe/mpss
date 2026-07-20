// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/attestation.h"
#include "mpss/mpss.h"
#include <memory>
#include <string_view>

namespace mpss::impl::os
{

/**
 * @brief Create a TPM-attested key on the Windows CNG backend.
 *
 * Produces real, nonce-bound attestation evidence via @c NCryptCreateClaim on a Platform Crypto
 * Provider key: a @ref mpss::AttestationFormat::windows_tpm_claim that is externally verifiable
 * (AIK -> EK -> published manufacturer root). Only a TPM claim counts as attestation. VBS / Key
 * Guard is key protection applied on the normal create path, not attestation evidence, so a
 * VBS-only key carries no evidence and reports @c supports_attestation() == false.
 *
 * @param[in] name The key name to create.
 * @param[in] algorithm The EC signature algorithm to use.
 * @param[in] request The nonce-bound attestation request (challenge must be non-empty).
 * @return A key pair carrying @ref mpss::AttestationEvidence, or nullptr if no TPM attestation
 * could be produced. The caller decides how to treat that outcome based on
 * @ref mpss::AttestationRequirement.
 */
[[nodiscard]]
std::unique_ptr<mpss::KeyPair> create_attested_key(std::string_view name, mpss::Algorithm algorithm,
                                                   const mpss::AttestationRequest &request);

} // namespace mpss::impl::os
