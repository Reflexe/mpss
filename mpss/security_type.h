// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"

#ifdef __cplusplus
#include <cstdint>

namespace mpss
{

/**
 * @brief The minimum security guarantee a key's private material is backed by.
 *
 * Each value is a floor guarantee, not an exact mechanism label. Reporting a value asserts that
 * the key provides every guarantee at that ordinal and below. A backend reports the strongest
 * value it can establish from trustworthy evidence and rounds down whenever the evidence cannot
 * support a stronger claim. @ref KeyInfo::storage_description remains the human-readable
 * mechanism detail and may be more specific than the guaranteed tier.
 *
 * The ordering represents a post-compromise healing guarantee. It does not encode exportability,
 * user authentication, PIN/touch policy, certification, provenance, or remote attestation. A
 * stronger tier does not imply that the key is attestable, and a weaker tier does not imply that
 * it is not.
 *
 * There is deliberately no member for indeterminate evidence. A usable key whose classification
 * evidence is unavailable or indeterminate is reported as @ref software. An operational failure
 * while retrieving that evidence fails the operation instead of manufacturing a tier.
 */
enum class SecurityType : std::uint8_t
{
    /// Protection is the ordinary OS/software storage boundary. It does not provide a
    /// post-compromise healing guarantee against a same-user attacker.
    software = 0,

    /// Hardware-assisted isolation that shares the main processor/silicon, such as Windows
    /// VBS/VSM or an Android TEE. Heals against an unprivileged same-user attacker, but not
    /// against a privileged platform compromise.
    mixed = 1,

    /// Dedicated hardware that resists privileged software compromise. This makes no claim of
    /// certified resistance to a determined physical attack.
    hardware = 2,

    /// A tamper-resistant secure element, resisting privileged local and direct physical attack.
    secure_element = 3,
};

/// The largest valid @ref SecurityType ordinal. Values above this are invalid at any boundary.
inline constexpr std::uint8_t max_security_type_value = static_cast<std::uint8_t>(SecurityType::secure_element);

/**
 * @brief Determines whether a guaranteed tier satisfies a required minimum.
 * @param[in] guaranteed The tier a key is guaranteed to provide.
 * @param[in] required The minimum tier the caller requires.
 * @return true if @p guaranteed is at least as strong as @p required.
 */
[[nodiscard]]
constexpr bool meets_minimum(SecurityType guaranteed, SecurityType required) noexcept
{
    return static_cast<std::uint8_t>(guaranteed) >= static_cast<std::uint8_t>(required);
}

/**
 * @brief Determines whether a raw integer names a defined @ref SecurityType.
 *
 * Boundaries that receive a tier as an integer (the C API, JNI, OpenSSL parameters) must call
 * this before casting. Out-of-range values fail the operation; they are never clamped.
 *
 * @param[in] value The raw value to validate.
 * @return true if @p value is one of the four defined ordinals.
 */
[[nodiscard]]
constexpr bool is_valid_security_type(std::uint64_t value) noexcept
{
    return value <= max_security_type_value;
}

/**
 * @brief Canonical lowercase name for a @ref SecurityType value, for diagnostics.
 */
[[nodiscard]]
constexpr const char *to_string(SecurityType security_type) noexcept
{
    switch (security_type)
    {
    case SecurityType::software:
        return "software";
    case SecurityType::mixed:
        return "mixed";
    case SecurityType::hardware:
        return "hardware";
    case SecurityType::secure_element:
        return "secure_element";
    }
    return "invalid";
}

} // namespace mpss
#endif // __cplusplus
