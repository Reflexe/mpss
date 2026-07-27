// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/backend_registry.h"

namespace mpss::impl::yubikey
{

/**
 * @brief Backend implementation for YubiKey PIV.
 */
class YubiKeyBackend : public Backend
{
  public:
    YubiKeyBackend() = default;
    ~YubiKeyBackend() override = default;

    [[nodiscard]]
    const char *name() const override;

    [[nodiscard]]
    bool is_algorithm_available(Algorithm algorithm, SecurityType min_security) const override;

    [[nodiscard]]
    std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                        SecurityType min_security) const override;

    [[nodiscard]]
    std::unique_ptr<KeyPair> open_key(std::string_view name, SecurityType min_security) const override;

    [[nodiscard]]
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                std::span<const std::byte> sig) const override;
};

} // namespace mpss::impl::yubikey
