// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"

#ifdef __cplusplus
namespace mpss
{

/**
 * @brief The level of protection backing a key's private material.
 */
enum class KeyProtection
{
    Software, ///< Protected purely in software.
    Mixed,    ///< Hardware-assisted isolation without a dedicated crypto module (e.g. Windows VBS).
    Hardware, ///< Bound to dedicated hardware (e.g. TPM, Secure Enclave, YubiKey).
};

/**
 * @brief Canonical lowercase name for a @ref KeyProtection value.
 */
[[nodiscard]] constexpr const char *to_string(KeyProtection protection) noexcept
{
    switch (protection)
    {
    case KeyProtection::Hardware:
        return "hardware";
    case KeyProtection::Mixed:
        return "mixed";
    case KeyProtection::Software:
        return "software";
    }
    return "software";
}

/**
 * @brief Structure to hold information about a key.
 */
// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)
struct MPSS_DECOR KeyInfo
{
    KeyInfo(KeyProtection protection, const char *storage_description)
        : protection{protection}, storage_description{storage_description}
    {
    }

    /**
     * @brief The level of protection backing the key's private material.
     */
    const KeyProtection protection;

    /**
     * @brief Description of the storage where the key is stored.
     */
    const char *storage_description;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)

} // namespace mpss
#endif // __cplusplus
