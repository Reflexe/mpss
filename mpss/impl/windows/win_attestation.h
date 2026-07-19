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
 * @brief Create a hardware-attested key on the Windows CNG backend.
 *
 * Produces real, nonce-bound attestation evidence via @c NCryptCreateClaim. A TPM claim is
 * preferred because it is externally verifiable (AIK -> EK -> manufacturer root); if no usable
 * TPM is available the function falls back to a VBS / Key Guard claim, which is emitted under the
 * distinct @ref mpss::AttestationFormat::windows_vbs_claim format (key-protection + CI-test-lane
 * only, never externally verifiable).
 *
 * @param[in] name The key name to create.
 * @param[in] algorithm The EC signature algorithm to use.
 * @param[in] request The nonce-bound attestation request (challenge must be non-empty).
 * @return A key pair carrying @ref mpss::AttestationEvidence, or nullptr if no evidence could be
 * produced (e.g. neither TPM nor VBS is available). The caller decides how to treat that outcome
 * based on @ref mpss::AttestationRequirement.
 */
[[nodiscard]]
std::unique_ptr<mpss::KeyPair> create_attested_key(std::string_view name, mpss::Algorithm algorithm,
                                                   const mpss::AttestationRequest &request);

} // namespace mpss::impl::os
