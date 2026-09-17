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
    software = 0,
    mixed = 1,
    hardware = 2
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
    KeyInfo(IsolationLevel isolation_level, const char *storage_description)
        : isolation_level{isolation_level}, storage_description{storage_description}
    {
    }

    /**
     * @brief Isolation level protecting the key's private material.
     */
    const IsolationLevel isolation_level;

    /**
     * @brief Description of the storage where the key is stored.
     */
    const char *storage_description;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)

} // namespace mpss
#endif // __cplusplus
