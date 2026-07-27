// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/impl/backend_registry.h"
#include "mpss/utils/utilities.h"
#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>

namespace mpss
{

namespace
{

// Guards the public entry points against a tier value that is not one of the four defined
// ordinals. Such a value can only arrive through a cast, and letting it through would index the
// availability cache out of bounds and compare greater than every valid floor.
[[nodiscard]]
bool check_valid_min_security(SecurityType min_security)
{
    if (!is_valid_security_type(static_cast<std::uint8_t>(min_security)))
    {
        utils::log_and_set_error("Invalid minimum security value {}.",
                                 static_cast<unsigned>(static_cast<std::uint8_t>(min_security)));
        return false;
    }
    return true;
}

} // namespace

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                         SecurityType min_security)
{
    utils::set_error({});
    if (!check_valid_min_security(min_security))
    {
        return nullptr;
    }
    utils::log_trace("KeyPair::Create called for key '{}' with algorithm '{}', minimum security '{}'.", name,
                     get_algorithm_info(algorithm).type_str, to_string(min_security));
    return impl::create_key(name, algorithm, policy, min_security);
}

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, std::string_view backend_name,
                                         KeyPolicy policy, SecurityType min_security)
{
    utils::set_error({});
    if (!check_valid_min_security(min_security))
    {
        return nullptr;
    }
    utils::log_trace(
        "KeyPair::Create called for key '{}' with algorithm '{}' on backend '{}', minimum security '{}'.", name,
        get_algorithm_info(algorithm).type_str, backend_name, to_string(min_security));
    return impl::create_key(backend_name, name, algorithm, policy, min_security);
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name, SecurityType min_security)
{
    utils::set_error({});
    if (!check_valid_min_security(min_security))
    {
        return nullptr;
    }
    utils::log_trace("KeyPair::Open called for key '{}' with minimum security '{}'.", name, to_string(min_security));
    return impl::open_key(name, min_security);
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name, std::string_view backend_name,
                                       SecurityType min_security)
{
    utils::set_error({});
    if (!check_valid_min_security(min_security))
    {
        return nullptr;
    }
    utils::log_trace("KeyPair::Open called for key '{}' on backend '{}' with minimum security '{}'.", name,
                     backend_name, to_string(min_security));
    return impl::open_key(backend_name, name, min_security);
}

bool is_algorithm_available(Algorithm algorithm, SecurityType min_security)
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        return false;
    }
    if (!check_valid_min_security(min_security))
    {
        return false;
    }

    // Cache results per (algorithm, minimum security) to avoid repeated expensive probes. Each
    // floor is a separate question -- a backend can support an algorithm at one floor and not at a
    // stronger one -- and each entry is filled in lazily, so a floor that is never requested is
    // never probed.
    static std::mutex cache_mutex;
    static std::array<std::array<std::optional<bool>, max_security_type_value + 1U>, algorithm_info.size()> cache{};

    const std::size_t idx = static_cast<std::size_t>(algorithm);
    const std::size_t floor_idx = static_cast<std::size_t>(min_security);
    {
        std::scoped_lock lock{cache_mutex};
        if (cache[idx][floor_idx])
        {
            // NOLINTBEGIN(bugprone-unchecked-optional-access) - guarded by the if above.
            utils::log_trace("Algorithm availability for '{}' at minimum security '{}' returned from cache: {}.",
                             info.type_str, to_string(min_security),
                             *cache[idx][floor_idx] ? "available" : "unavailable");
            return *cache[idx][floor_idx];
            // NOLINTEND(bugprone-unchecked-optional-access)
        }
    }

    // Delegate to the default backend.
    utils::log_trace("Probing algorithm availability for '{}' at minimum security '{}'.", info.type_str,
                     to_string(min_security));
    const bool available = impl::is_algorithm_available(algorithm, min_security);

    // Cache positive results only. A positive is stable — the platform genuinely supports the algorithm.
    // A negative is the only direction that can be wrong and stick: a one-time probe can fail while the
    // keystore is temporarily unavailable (e.g. a locked device on a long-lived process) or a probe name
    // briefly collides, which memoizing would turn into a permanent, process-wide understatement of
    // availability. Re-probing a genuinely unsupported algorithm is cheap (create_key bails before
    // persisting a key), so negatives are simply not cached.
    if (available)
    {
        std::scoped_lock lock{cache_mutex};
        cache[idx][floor_idx] = true;
    }
    utils::log_trace("Algorithm '{}' at minimum security '{}' is {}.", info.type_str, to_string(min_security),
                     available ? "available" : "unavailable");
    return available;
}

bool is_algorithm_available(Algorithm algorithm, std::string_view backend_name, SecurityType min_security)
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        return false;
    }
    if (!check_valid_min_security(min_security))
    {
        return false;
    }

    // Cached the same way as the default-backend overload, but keyed by backend as well. Probing
    // creates and deletes a real key, which on a token or a TPM is slow and user-visible, so a
    // repeated question is answered from the cache.
    static std::mutex cache_mutex;
    static std::map<std::tuple<std::string, Algorithm, SecurityType>, bool, std::less<>> cache;
    auto cache_key = std::make_tuple(std::string{backend_name}, algorithm, min_security);
    {
        const std::scoped_lock lock{cache_mutex};
        const auto it = cache.find(cache_key);
        if (cache.end() != it)
        {
            utils::log_trace("Algorithm availability for '{}' on backend '{}' at minimum security '{}' returned "
                             "from cache: {}.",
                             info.type_str, backend_name, to_string(min_security),
                             it->second ? "available" : "unavailable");
            return it->second;
        }
    }

    utils::log_trace("Checking algorithm availability for '{}' on backend '{}' at minimum security '{}'.",
                     info.type_str, backend_name, to_string(min_security));
    const bool available = impl::is_algorithm_available(backend_name, algorithm, min_security);

    // Positive results only, for the same reason as the default-backend overload: a negative can be
    // a transient condition (a locked device, an unplugged token) that must not become permanent.
    if (available)
    {
        const std::scoped_lock lock{cache_mutex};
        cache.emplace(std::move(cache_key), true);
    }
    return available;
}

std::vector<Algorithm> get_available_algorithms()
{
    std::vector<Algorithm> result;
    for (const auto &[alg, info] : algorithm_info)
    {
        if (Algorithm::unsupported == alg)
        {
            continue;
        }
        if (is_algorithm_available(alg))
        {
            result.push_back(alg);
        }
    }
    return result;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    utils::set_error({});
    utils::log_trace("Standalone verify called with algorithm '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, hash.size(), sig.size());
    return impl::verify(hash, public_key, algorithm, sig);
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig, std::string_view backend_name)
{
    utils::set_error({});
    utils::log_trace("Standalone verify called with algorithm '{}' on backend '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, backend_name, hash.size(), sig.size());
    return impl::verify(backend_name, hash, public_key, algorithm, sig);
}

std::vector<const char *> get_available_backends()
{
    return impl::get_available_backends();
}

const char *get_default_backend_name()
{
    return impl::get_default_backend_name();
}

std::string get_error()
{
    return utils::get_error();
}

std::size_t KeyPair::sign_hash_size() const
{
    return utils::get_max_signature_size(algorithm());
}

std::size_t KeyPair::extract_key_size() const
{
    return utils::get_public_key_size(algorithm());
}

bool KeyPair::delete_key()
{
    utils::set_error({});
    return do_delete_key();
}

std::size_t KeyPair::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    utils::set_error({});
    if (sig.empty())
    {
        // An empty signature buffer is a request for the required signature size.
        return utils::get_max_signature_size(algorithm());
    }
    if (!utils::check_exact_hash_size(hash, algorithm()))
    {
        return 0;
    }
    if (!utils::check_sufficient_signature_buffer_size(sig, algorithm()))
    {
        return 0;
    }
    return do_sign_hash(hash, sig);
}

bool KeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    utils::set_error({});
    if (hash.empty() || sig.empty())
    {
        utils::log_and_set_error("Nothing to verify.");
        return false;
    }
    if (!utils::check_exact_hash_size(hash, algorithm()))
    {
        return false;
    }
    return do_verify(hash, sig);
}

std::size_t KeyPair::extract_key(std::span<std::byte> public_key) const
{
    utils::set_error({});
    if (public_key.empty())
    {
        // An empty output buffer is a request for the required public key size.
        return utils::get_public_key_size(algorithm());
    }
    if (!utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }
    return do_extract_key(public_key);
}

KeyPair::KeyPair(Algorithm algorithm, SecurityType security_type, const char *storage_description)
    : algorithm_{algorithm}, info_{get_algorithm_info(algorithm)}, key_info_{security_type, storage_description}
{
    if (0 == info_.key_bits)
    {
        utils::log_and_set_error("Unsupported algorithm '{}'.", info_.type_str);
    }
}

} // namespace mpss
