// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/noop/noop_backend.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <vector>

namespace mpss::impl::noop
{

namespace
{

// A key as the backend stores it. There is no private material: verification derives everything it
// needs from the public bytes, which is exactly why this backend must never be used for anything
// but tests.
struct KeyState
{
    Algorithm algorithm{Algorithm::unsupported};
    std::vector<std::byte> public_key;
};

std::mutex &store_mutex()
{
    static std::mutex mutex;
    return mutex;
}

// Guarded by store_mutex().
std::map<std::string, KeyState, std::less<>> &store()
{
    static std::map<std::string, KeyState, std::less<>> keys;
    return keys;
}

// Guarded by store_mutex().
Settings &settings()
{
    static Settings current;
    return current;
}

std::vector<std::byte> make_public_key(Algorithm algorithm)
{
    const std::size_t size = mpss::utils::get_public_key_size(algorithm);
    if (0 == size)
    {
        return {};
    }

    std::vector<std::byte> public_key(size);
    public_key[0] = std::byte{0x04}; // Uncompressed point indicator, as the real backends emit.

    std::random_device rng;
    std::uniform_int_distribution<unsigned int> dist(0, 0xFFU);
    std::ranges::generate(public_key.begin() + 1, public_key.end(),
                          [&] { return static_cast<std::byte>(dist(rng)); });
    return public_key;
}

// Deterministic, non-cryptographic signature over the hash, bound to the key's public bytes so a
// signature made with one key does not verify under another.
std::vector<std::byte> compute_signature(std::span<const std::byte> hash, std::span<const std::byte> public_key,
                                         Algorithm algorithm)
{
    const std::size_t size = mpss::utils::get_max_signature_size(algorithm);
    if (0 == size || hash.empty() || public_key.size() < 2)
    {
        return {};
    }

    std::vector<std::byte> sig(size);
    for (std::size_t i = 0; i < size; ++i)
    {
        const std::byte hash_byte = hash[i % hash.size()];
        const std::byte key_byte = public_key[1 + (i % (public_key.size() - 1))];
        sig[i] = hash_byte ^ key_byte;
    }
    return sig;
}

class NoopKeyPair : public mpss::KeyPair
{
  public:
    NoopKeyPair(std::string key_name, Algorithm algorithm, std::vector<std::byte> public_key,
                SecurityType security_type)
        : mpss::KeyPair(algorithm, security_type, "In-Memory Test Storage"), name_{std::move(key_name)},
          public_key_{std::move(public_key)}
    {
    }

    ~NoopKeyPair() override = default;

    bool do_delete_key() override
    {
        const std::scoped_lock lock{store_mutex()};
        if (settings().fail_delete)
        {
            mpss::utils::log_and_set_error("The noop backend was configured to fail deletion of key '{}'.", name_);
            return false;
        }

        if (0 == store().erase(name_))
        {
            mpss::utils::log_and_set_error("Key '{}' does not exist.", name_);
            return false;
        }

        released_ = true;
        return true;
    }

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override
    {
        if (released_)
        {
            mpss::utils::log_and_set_error("Key '{}' has been released.", name_);
            return 0;
        }

        const std::vector<std::byte> computed = compute_signature(hash, public_key_, algorithm());
        if (computed.empty() || sig.size() < computed.size())
        {
            mpss::utils::log_and_set_error("Could not sign with key '{}'.", name_);
            return 0;
        }

        std::ranges::copy(computed, sig.begin());
        return computed.size();
    }

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override
    {
        if (released_)
        {
            mpss::utils::log_and_set_error("Key '{}' has been released.", name_);
            return false;
        }

        const std::vector<std::byte> expected = compute_signature(hash, public_key_, algorithm());
        return !expected.empty() && std::ranges::equal(expected, sig);
    }

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override
    {
        if (released_)
        {
            mpss::utils::log_and_set_error("Key '{}' has been released.", name_);
            return 0;
        }

        if (public_key.size() < public_key_.size())
        {
            mpss::utils::log_and_set_error("Public key buffer is too small.");
            return 0;
        }

        std::ranges::copy(public_key_, public_key.begin());
        return public_key_.size();
    }

    void release_key() noexcept override
    {
        released_ = true;
    }

  private:
    std::string name_;
    std::vector<std::byte> public_key_;
    bool released_{false};
};

} // namespace

std::unique_ptr<KeyPair> NoopBackend::create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                                 [[maybe_unused]] SecurityType min_security) const
{
    if (KeyPolicy::none != policy)
    {
        mpss::utils::log_and_set_error("The noop backend does not support the requested key policy.");
        return nullptr;
    }

    const std::size_t public_key_size = mpss::utils::get_public_key_size(algorithm);
    if (0 == public_key_size)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    const std::string key_name{name};
    std::vector<std::byte> public_key = make_public_key(algorithm);

    const std::scoped_lock lock{store_mutex()};
    if (store().contains(key_name))
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    store().emplace(key_name, KeyState{algorithm, public_key});

    // The floor is intentionally not applied here: the registry owns that postcondition, and this
    // backend exists to prove it holds even for a backend that does nothing about it.
    return std::make_unique<NoopKeyPair>(key_name, algorithm, std::move(public_key), settings().security_type);
}

std::unique_ptr<KeyPair> NoopBackend::open_key(std::string_view name,
                                               [[maybe_unused]] SecurityType min_security) const
{
    const std::scoped_lock lock{store_mutex()};
    const auto it = store().find(name);
    if (store().end() == it)
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
        return nullptr;
    }

    // Classify on every open rather than replaying what create reported, which is what a real
    // backend does when it re-derives a key's evidence.
    return std::make_unique<NoopKeyPair>(std::string{name}, it->second.algorithm, it->second.public_key,
                                         settings().security_type);
}

bool NoopBackend::verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                         std::span<const std::byte> sig) const
{
    const std::vector<std::byte> expected = compute_signature(hash, public_key, algorithm);
    return !expected.empty() && std::ranges::equal(expected, sig);
}

void set_settings(const Settings &new_settings)
{
    const std::scoped_lock lock{store_mutex()};
    settings() = new_settings;
}

Settings get_settings()
{
    const std::scoped_lock lock{store_mutex()};
    return settings();
}

void reset()
{
    const std::scoped_lock lock{store_mutex()};
    settings() = Settings{};
    store().clear();
}

} // namespace mpss::impl::noop
