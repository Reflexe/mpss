// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/utils/unique_resource.h"
#include "mpss/utils/utilities.h"
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

// Owns a key that is already persisted in a provider but has not yet been committed to the caller.
// Dropping it removes the key rather than merely closing the handle, so a creation that fails
// part-way leaves nothing behind; release() commits the key and hands ownership over.
// NCryptDeleteKey frees the handle itself on success; if the delete fails the handle is still
// closed so it cannot leak, and the failure is logged because the key may survive on the system.
struct NcryptUncommittedKeyDeleter
{
    void operator()(NCRYPT_KEY_HANDLE handle) const noexcept
    {
        if (ERROR_SUCCESS != ::NCryptDeleteKey(handle, /* dwFlags */ 0))
        {
            mpss::utils::log_warning(
                "Could not delete a partially created key; manual cleanup may be required.");
            ::NCryptFreeObject(handle);
        }
    }
};

using NcryptUncommittedKey = mpss::utils::UniqueResource<NCRYPT_KEY_HANDLE, NcryptUncommittedKeyDeleter>;

} // namespace mpss::impl::os
