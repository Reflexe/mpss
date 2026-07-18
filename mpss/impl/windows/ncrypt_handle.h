// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <Windows.h>
#include <ncrypt.h>
#include <utility>

namespace mpss::impl::os
{

// Move-only owner for an NCRYPT handle; frees it with NCryptFreeObject on destruction.
// NCRYPT_PROV_HANDLE and NCRYPT_KEY_HANDLE are both ULONG_PTR, so one type owns either.
class NcryptHandle
{
  public:
    NcryptHandle() = default;
    explicit NcryptHandle(NCRYPT_HANDLE handle) noexcept : handle_(handle) {}

    NcryptHandle(NcryptHandle &&other) noexcept : handle_(std::exchange(other.handle_, 0)) {}
    NcryptHandle &operator=(NcryptHandle &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            handle_ = std::exchange(other.handle_, 0);
        }
        return *this;
    }

    NcryptHandle(const NcryptHandle &) = delete;
    NcryptHandle &operator=(const NcryptHandle &) = delete;

    ~NcryptHandle()
    {
        reset();
    }

    NCRYPT_HANDLE get() const noexcept
    {
        return handle_;
    }

    explicit operator bool() const noexcept
    {
        return 0 != handle_;
    }

    // Address for an NCrypt out-parameter (e.g. NCryptOpenKey). Must be called on an empty handle;
    // the wrapper then owns whatever the call stores.
    NCRYPT_HANDLE *put() noexcept
    {
        return &handle_;
    }

    void reset() noexcept
    {
        if (0 != handle_)
        {
            ::NCryptFreeObject(handle_);
            handle_ = 0;
        }
    }

  private:
    NCRYPT_HANDLE handle_ = 0;
};

} // namespace mpss::impl::os
