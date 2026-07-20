// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace mpss::impl::os
{

/**
 * @brief Assemble an externally-verifiable offline VBS attestation bundle.
 *
 * Wraps the already-generated NCrypt VBS/Key Guard claim (@p vbs_claim, which binds the attested
 * key and @p challenge) together with the TPM measured-boot evidence that anchors the VBS root
 * (IDK) to the platform TPM: an AIK-signed platform quote over all PCRs, the SRTM measured-boot
 * TCG log, and the AIK public key. The result follows Microsoft's documented Azure Attestation
 * "VBS protocol" JSON shape (att_type "vbs"), so a relying party can validate it offline:
 * AIK quote -> PCR replay of the log -> the IDK measured into the log -> the VBS claim's signature.
 *
 * Producing the TPM anchor requires a functioning platform TPM (physical or virtual). Returns
 * @c std::nullopt if the AIK, platform quote, or measured-boot log cannot be obtained, in which
 * case the caller emits the bare claim (which a relying party then refuses as un-anchored).
 *
 * @param[in] vbs_claim The NCrypt VBS_ROOT claim over the subject key (the "vsm_report").
 * @param[in] challenge The relying-party nonce, bound into both the claim and the platform quote.
 * @return UTF-8 JSON bundle bytes, or @c std::nullopt if the TPM anchor is unavailable.
 */
[[nodiscard]]
std::optional<std::vector<std::byte>> build_vbs_offline_bundle(std::span<const std::byte> vbs_claim,
                                                               std::span<const std::byte> challenge);

} // namespace mpss::impl::os
