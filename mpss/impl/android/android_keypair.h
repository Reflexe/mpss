// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <cstdint>
#include <optional>

namespace mpss::impl::os
{

[[nodiscard]]
constexpr std::optional<StorageTier> storage_tier_for_security_level(int level)
{
    switch (level)
    {
    case 0:
        return StorageTier::unknown;
    case 1:
        return StorageTier::android_software;
    case 2:
        return StorageTier::android_unknown_secure;
    case 3:
        return StorageTier::android_trusted_environment;
    case 4:
        return StorageTier::android_strongbox;
    default:
        return std::nullopt;
    }
}

class AndroidKeyPair : public mpss::KeyPair
{
  public:
    AndroidKeyPair(mpss::Algorithm algorithm, std::string_view name, mpss::StorageTier storage_tier,
                   std::uint64_t generation)
        : mpss::KeyPair{algorithm, storage_tier}, key_name_{name}, generation_{generation}
    {
    }

    ~AndroidKeyPair() override
    {
        release_from_destructor();
    }

  protected:
    bool do_release_key() override;

    bool do_delete_key() override;

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;

  private:
    bool close_key();

    std::string key_name_;

    // The cache entry this handle took its hold on, handed back when closing so that a name
    // deleted and created again while this handle was alive cannot have this release charged
    // against the key that now holds the name.
    std::uint64_t generation_;
};

} // namespace mpss::impl::os
