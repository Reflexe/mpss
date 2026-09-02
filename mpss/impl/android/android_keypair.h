// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <cstdint>
#include <optional>

namespace mpss::impl::os
{

[[nodiscard]]
std::optional<KeyInfo> android_key_info_from_security_level(std::int32_t security_level) noexcept;

[[nodiscard]]
bool delete_android_key(std::string_view key_name);

[[nodiscard]]
bool close_android_key(std::string_view key_name);

class AndroidKeyPair : public mpss::KeyPair
{
  public:
    AndroidKeyPair(mpss::Algorithm algorithm, std::string_view name, IsolationLevel isolation_level,
                   const char *storage_description)
        : mpss::KeyPair{algorithm, isolation_level, storage_description}, key_name_{name}
    {
    }

    ~AndroidKeyPair() override
    {
        try
        {
            close_key();
        }
        // NOLINTNEXTLINE(bugprone-empty-catch) - a destructor must not propagate exceptions.
        catch (...)
        {
        }
    }

    void release_key() override;

  protected:
    bool do_delete_key() override;

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;

  private:
    void close_key();

    std::string key_name_;
};

} // namespace mpss::impl::os
