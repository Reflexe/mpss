// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include "mpss/security_type.h"

#ifdef __cplusplus
namespace mpss
{

/**
 * @brief Structure to hold information about a key.
 */
// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)
struct MPSS_DECOR KeyInfo
{
    KeyInfo(SecurityType security_type, const char *storage_description)
        : security_type{security_type}, storage_description{storage_description}
    {
    }

    /**
     * @brief The minimum security guarantee backing the key's private material.
     */
    const SecurityType security_type;

    /**
     * @brief Description of the storage where the key is stored.
     */
    const char *storage_description;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)

} // namespace mpss
#endif // __cplusplus
