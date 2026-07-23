// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/utils/unique_resource.h"
#include <Windows.h>
#include <ncrypt.h>

namespace mpss::impl::os
{

// Releases an owned NCRYPT handle. NCRYPT_PROV_HANDLE and NCRYPT_KEY_HANDLE are both ULONG_PTR,
// so a single owner type works for either.
struct NcryptDeleter
{
    void operator()(NCRYPT_HANDLE handle) const noexcept
    {
        ::NCryptFreeObject(handle);
    }
};

using NcryptHandle = mpss::utils::UniqueResource<NCRYPT_HANDLE, NcryptDeleter>;

} // namespace mpss::impl::os
