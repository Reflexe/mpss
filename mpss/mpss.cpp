// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/impl/backend_registry.h"
#include "mpss/utils/utilities.h"
#include <array>
#include <mutex>
#include <optional>

namespace mpss
{

namespace
{
static constexpr std::size_t isolation_level_count =
    static_cast<std::size_t>(IsolationLevel::hardware) + 1;

struct DefaultAvailabilityCache
{
    std::mutex mutex;
    std::array<std::array<std::optional<bool>, isolation_level_count>, algorithm_info.size()> entries{};
};

DefaultAvailabilityCache &default_availability_cache()
{
    // Availability remains callable from host static destructors.
    static DefaultAvailabilityCache &cache =
        *new DefaultAvailabilityCache(); // NOLINT(cppcoreguidelines-owning-memory)
    return cache;
}

// Success is the truthy result: a non-null key, true, or a non-zero size. Explicit conversions are
// permitted, so that std::unique_ptr qualifies.
template <typename T>
concept boolean_testable = requires(const T &value) { static_cast<bool>(value); };

// A successful operation never reports an error. A backend may set one on an internal step - an
// existence probe, a provider fallback - and still succeed, so success is normalized here rather
// than in each backend.
template <boolean_testable T>
[[nodiscard]]
T clear_error_on_success(T result)
{
    if (static_cast<bool>(result))
    {
        clear_error();
    }
    return result;
}
} // namespace

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                         IsolationLevel minimum_isolation)
{
    clear_error();
    utils::log_trace("KeyPair::Create called for key '{}' with algorithm '{}'.", name,
                     get_algorithm_info(algorithm).type_str);
    return clear_error_on_success(impl::create_key(name, algorithm, policy, minimum_isolation));
}

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, std::string_view backend_name,
                                         KeyPolicy policy, IsolationLevel minimum_isolation)
{
    clear_error();
    utils::log_trace("KeyPair::Create called for key '{}' with algorithm '{}' on backend '{}'.", name,
                     get_algorithm_info(algorithm).type_str, backend_name);
    return clear_error_on_success(impl::create_key(backend_name, name, algorithm, policy, minimum_isolation));
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name, IsolationLevel minimum_isolation)
{
    clear_error();
    utils::log_trace("KeyPair::Open called for key '{}'.", name);
    return clear_error_on_success(impl::open_key(name, minimum_isolation));
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name, std::string_view backend_name,
                                       IsolationLevel minimum_isolation)
{
    clear_error();
    utils::log_trace("KeyPair::Open called for key '{}' on backend '{}'.", name, backend_name);
    return clear_error_on_success(impl::open_key(backend_name, name, minimum_isolation));
}

bool is_algorithm_available(Algorithm algorithm, IsolationLevel minimum_isolation)
{
    clear_error();
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        utils::log_and_set_error("Unknown or unsupported algorithm.");
        return false;
    }

    const std::size_t algorithm_index = static_cast<std::size_t>(algorithm);
    const std::size_t isolation_index = static_cast<std::size_t>(minimum_isolation);
    if (isolation_index >= isolation_level_count)
    {
        return impl::is_algorithm_available(algorithm, minimum_isolation);
    }

    DefaultAvailabilityCache &cache = default_availability_cache();
    {
        std::scoped_lock lock{cache.mutex};
        if (cache.entries[algorithm_index][isolation_index])
        {
            // NOLINTBEGIN(bugprone-unchecked-optional-access) - guarded by the if above.
            utils::log_trace("Algorithm availability for '{}' at minimum isolation {} returned from cache: {}.",
                             info.type_str, isolation_index,
                             *cache.entries[algorithm_index][isolation_index] ? "available" : "unavailable");
            return *cache.entries[algorithm_index][isolation_index];
            // NOLINTEND(bugprone-unchecked-optional-access)
        }
    }

    utils::log_trace("Probing algorithm availability for '{}'.", info.type_str);
    const bool available = impl::is_algorithm_available(algorithm, minimum_isolation);
    if (available)
    {
        std::scoped_lock lock{cache.mutex};
        cache.entries[algorithm_index][isolation_index] = true;
    }
    utils::log_trace("Algorithm '{}' is {}.", info.type_str, available ? "available" : "unavailable");
    return available;
}

bool is_algorithm_available(Algorithm algorithm, std::string_view backend_name, IsolationLevel minimum_isolation)
{
    clear_error();
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        utils::log_and_set_error("Unknown or unsupported algorithm.");
        return false;
    }
    utils::log_trace("Checking algorithm availability for '{}' on backend '{}'.", info.type_str, backend_name);
    return impl::is_algorithm_available(backend_name, algorithm, minimum_isolation);
}

std::vector<Algorithm> get_available_algorithms(IsolationLevel minimum_isolation)
{
    clear_error();
    std::vector<Algorithm> result;
    for (const auto &[alg, info] : algorithm_info)
    {
        if (Algorithm::unsupported == alg)
        {
            continue;
        }
        if (is_algorithm_available(alg, minimum_isolation))
        {
            result.push_back(alg);
        }
    }
    return result;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    clear_error();
    utils::log_trace("Standalone verify called with algorithm '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, hash.size(), sig.size());
    return clear_error_on_success(impl::verify(hash, public_key, algorithm, sig));
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig, std::string_view backend_name)
{
    clear_error();
    utils::log_trace("Standalone verify called with algorithm '{}' on backend '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, backend_name, hash.size(), sig.size());
    return clear_error_on_success(impl::verify(backend_name, hash, public_key, algorithm, sig));
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

bool has_error() noexcept
{
    return utils::has_error();
}

void clear_error() noexcept
{
    utils::clear_error();
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
    clear_error();
    return clear_error_on_success(do_delete_key());
}

std::size_t KeyPair::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    clear_error();
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
    return clear_error_on_success(do_sign_hash(hash, sig));
}

bool KeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    clear_error();
    if (hash.empty() || sig.empty())
    {
        utils::log_and_set_error("Nothing to verify.");
        return false;
    }
    if (!utils::check_exact_hash_size(hash, algorithm()))
    {
        return false;
    }
    return clear_error_on_success(do_verify(hash, sig));
}

std::size_t KeyPair::extract_key(std::span<std::byte> public_key) const
{
    clear_error();
    if (public_key.empty())
    {
        // An empty output buffer is a request for the required public key size.
        return utils::get_public_key_size(algorithm());
    }
    if (!utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }
    return clear_error_on_success(do_extract_key(public_key));
}

KeyPair::KeyPair(Algorithm algorithm, IsolationLevel isolation_level, const char *storage_description)
    : algorithm_{algorithm}, info_{get_algorithm_info(algorithm)}, key_info_{isolation_level, storage_description}
{
    if (0 == info_.key_bits)
    {
        utils::log_and_set_error("Unsupported algorithm '{}'.", info_.type_str);
    }
}

} // namespace mpss
