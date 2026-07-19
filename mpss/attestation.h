// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include <cstddef>
#include <variant>
#include <vector>

namespace mpss
{

/**
 * @brief The concrete, vendor-defined format of a piece of attestation evidence.
 *
 * The format is the sole signal that identifies how evidence must be parsed and verified.
 * VBS and TPM claims are deliberately distinct formats: a relying party that requires
 * externally-verifiable attestation simply refuses @ref AttestationFormat::windows_vbs_claim,
 * which cannot chain to a published root.
 */
enum class AttestationFormat
{
    /** @brief No evidence. */
    none,
    /** @brief Android Key Attestation: X.509 chain, leaf extension 1.3.6.1.4.1.11129.2.1.17. */
    android_key_attestation,
    /** @brief Apple ACME Managed Device Attestation: X.509 chain (device-attest-01). */
    apple_acme_managed_device,
    /** @brief Windows TPM claim (NCryptCreateClaim, AUTHORITY_AND_SUBJECT / PLATFORM); externally verifiable. */
    windows_tpm_claim,
    /** @brief Windows VBS / Key Guard claim; key protection + CI test lane only, NOT externally verifiable. */
    windows_vbs_claim
};

/**
 * @brief Whether attestation is merely requested (best-effort) or strictly required.
 */
enum class AttestationRequirement
{
    /** @brief Produce evidence if the backend can; otherwise create the key without it. */
    request,
    /** @brief Fail key creation if evidence cannot be produced. */
    require
};

/**
 * @brief A nonce-bound request for attestation evidence at key creation.
 *
 * The @ref challenge is the relying party's nonce; it is bound inside the vendor-signed
 * evidence so the relying party can prove freshness. The challenge must be non-empty.
 */
struct AttestationRequest
{
    /** @brief Relying-party nonce bound into the evidence. Must not be empty. */
    std::vector<std::byte> challenge;

    /** @brief Whether evidence is best-effort or strictly required. */
    AttestationRequirement requirement{AttestationRequirement::request};
};

/** @brief A DER-encoded X.509 certificate chain, leaf-first (Android Key Attestation, Apple ACME). */
using CertChain = std::vector<std::vector<std::byte>>;

/** @brief An opaque Windows NCrypt claim blob (TPM or VBS). */
using NCryptClaim = std::vector<std::byte>;

/**
 * @brief Vendor-signed attestation evidence for a newly created key.
 *
 * There is no application-defined framing: the nonce and public key are read from the
 * signed structure (X.509 chain or NCrypt claim), never from an app-defined blob. The
 * @ref payload variant carries the format-appropriate representation; @c std::monostate
 * corresponds to @ref AttestationFormat::none.
 */
struct AttestationEvidence
{
    /** @brief The concrete evidence format. Also the signal for how to verify it. */
    AttestationFormat format{AttestationFormat::none};

    /** @brief The signed evidence: a cert chain (Android/Apple) or an NCrypt claim (Windows). */
    std::variant<std::monostate, CertChain, NCryptClaim> payload;
};

/**
 * @brief What kind of attestation a backend is able to produce.
 */
enum class AttestationCapability
{
    /** @brief The backend cannot attest keys. */
    none,
    /** @brief The backend attests the key itself (Android, Apple ACME, Windows). */
    key_attestation
};

} // namespace mpss
