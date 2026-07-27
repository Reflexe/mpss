// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/backend_registry.h"

namespace mpss::impl::noop
{

/**
 * @brief In-memory backend used to exercise backend-independent behavior.
 *
 * This backend is compiled only when MPSS_BACKEND_NOOP is enabled, is never selected as the
 * platform default, and is reachable only by explicit backend name ("noop") or through
 * MPSS_DEFAULT_BACKEND. It exists so that the generic create/open/floor/cleanup logic in the
 * registry can be tested on every platform, including ones with no OS backend at all.
 *
 * It performs no cryptography. Keys live in process memory and its signatures are a deterministic,
 * non-cryptographic function of the hash and the key's public bytes; they are self-consistent, so
 * sign/verify round-trips and availability probing behave normally, and nothing more.
 *
 * It also deliberately does not prune mechanisms by the requested floor or enforce that floor
 * itself. That is what makes it useful: it lets the tests observe the enforcement the registry
 * applies on top of any backend.
 */
class NoopBackend : public Backend
{
  public:
    NoopBackend() = default;

    ~NoopBackend() override = default;

    [[nodiscard]]
    const char *name() const override
    {
        return "noop";
    }

    [[nodiscard]]
    std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                        SecurityType min_security) const override;

    [[nodiscard]]
    std::unique_ptr<KeyPair> open_key(std::string_view name, SecurityType min_security) const override;

    [[nodiscard]]
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                std::span<const std::byte> sig) const override;
};

/**
 * @brief Test-controlled behavior of the noop backend.
 */
struct Settings
{
    /// The guarantee the backend reports for every key it creates or opens. Classification happens
    /// on each create and each open, so changing this between a create and a later open makes the
    /// same key report a different tier, the way a real backend re-derives evidence on reopen.
    SecurityType security_type{SecurityType::software};

    /// When true, deleting a key fails and the key is kept. Used to exercise the cleanup-failure
    /// path after a key is rejected for being below the requested floor.
    bool fail_delete{false};
};

/// @brief Replaces the backend's current settings.
MPSS_DECOR void set_settings(const Settings &settings);

/// @brief Returns the backend's current settings.
[[nodiscard]]
MPSS_DECOR Settings get_settings();

/// @brief Restores default settings and discards every in-memory key.
MPSS_DECOR void reset();

} // namespace mpss::impl::noop
