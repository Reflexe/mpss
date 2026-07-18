// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include "mpss/key_policy.h"
#include <cstddef>
#include <vector>

namespace mpss
{

/**
 * @brief Controls how key creation handles backend attestation.
 */
enum class MPSS_DECOR AttestationMode
{
    /** @brief Do not request attestation. */
    none = 0,
    /** @brief Use attestation when supported; otherwise still create the key. */
    if_supported,
    /** @brief Require attestation; fail key creation if attestation is unavailable or fails. */
    required,
};

/**
 * @brief Outcome of the attestation portion of key creation.
 */
enum class MPSS_DECOR AttestationStatus
{
    /** @brief Attestation was not requested. */
    not_requested = 0,
    /** @brief The selected backend does not support the requested attestation flow. */
    unsupported,
    /** @brief Attestation completed and returned backend-specific data. */
    performed,
    /** @brief Attestation was requested but key creation or attestation failed. */
    failed,
};

/**
 * @brief Attestation-related key creation options.
 */
struct MPSS_DECOR AttestationOptions
{
    /** @brief Attestation mode for key creation. */
    AttestationMode mode{AttestationMode::none};

    /** @brief Optional backend-specific nonce to bind into attestation output. */
    std::vector<std::byte> nonce;
};

/**
 * @brief Advanced key creation options.
 */
struct MPSS_DECOR KeyCreationOptions
{
    /** @brief Backend-specific key policy. */
    KeyPolicy policy{KeyPolicy::none};

    /** @brief Attestation options for this creation request. */
    AttestationOptions attestation;
};

/**
 * @brief Result of the attestation portion of key creation.
 */
struct MPSS_DECOR AttestationResult
{
    /** @brief Whether attestation was requested, unsupported, performed, or failed. */
    AttestationStatus status{AttestationStatus::not_requested};

    /** @brief Optional opaque backend-specific attestation payload. */
    std::vector<std::byte> document;

    /** @brief Echoed nonce associated with the attestation request/result. */
    std::vector<std::byte> nonce;
};

} // namespace mpss
