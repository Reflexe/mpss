// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/utils/utilities.h"

namespace mpss_openssl::utils
{

/** @brief Reported when a failure has no message of its own, because building one would throw. */
inline constexpr const char *internal_error_message = "Internal error.";

/**
 * @brief Records an internal failure, so it is not mistaken for a clean negative.
 *
 * The value returned after catching an exception is the same one "no such key" returns. Only a
 * non-empty error tells the two apart.
 */
inline void set_internal_error() noexcept
{
    try
    {
        mpss::utils::set_error(internal_error_message);
    }
    catch (...) // The exception being handled may be an allocation failure.
    {
    }
}

} // namespace mpss_openssl::utils
