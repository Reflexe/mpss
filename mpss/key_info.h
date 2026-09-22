// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include <cstdint>

#ifdef __cplusplus
namespace mpss
{

/**
 * @brief Isolation level protecting a key's private material.
 */
enum class IsolationLevel : std::uint8_t
{
    unspecified = 0,
    software = 1,
    mixed = 2,
    hardware = 3
};

[[nodiscard]]
constexpr bool meets_minimum_isolation(IsolationLevel actual, IsolationLevel minimum) noexcept
{
    return static_cast<std::uint8_t>(actual) >= static_cast<std::uint8_t>(minimum);
}

/**
 * @brief Structure to hold information about a key.
 */
// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)
struct MPSS_DECOR KeyInfo
{
    KeyInfo(bool hardware_backed, const char *storage_description)
        : isolation_level{IsolationLevel::unspecified}, is_hardware_backed{hardware_backed},
          storage_description{storage_description}
    {
    }

    KeyInfo(IsolationLevel isolation_level, const char *storage_description)
        : isolation_level{isolation_level},
          is_hardware_backed{IsolationLevel::mixed == isolation_level || IsolationLevel::hardware == isolation_level},
          storage_description{storage_description}
    {
    }

    /**
     * @brief Isolation level protecting the key's private material.
     */
    const IsolationLevel isolation_level;

    /**
     * @brief Legacy hardware-backed indicator.
     */
    const bool is_hardware_backed;

    /**
     * @brief Description of the storage where the key is stored.
     */
    const char *storage_description;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)

} // namespace mpss
#endif // __cplusplus
