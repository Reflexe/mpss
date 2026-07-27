// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/windows/ncrypt_handle.h"
#include "mpss/mpss.h"
#include <Windows.h>
#include <ncrypt.h>

namespace mpss::impl::os
{

class WindowsKeyPair : public mpss::KeyPair
{
  public:
    WindowsKeyPair(mpss::Algorithm algorithm, NCRYPT_KEY_HANDLE handle, mpss::SecurityType security_type,
                   const char *storage_description)
        : mpss::KeyPair(algorithm, security_type, storage_description), key_handle_{handle}
    {
    }

    ~WindowsKeyPair() override = default;

    bool do_delete_key() override;

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;

    void release_key() noexcept override;

  private:
    NcryptHandle key_handle_;
};

} // namespace mpss::impl::os
