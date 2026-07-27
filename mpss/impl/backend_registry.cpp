// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/backend_registry.h"
#include "mpss/config.h"
#include "mpss/impl/os_backend.h"
#ifdef MPSS_BACKEND_YUBIKEY
#include "mpss/impl/yubikey/yk_backend.h"
#endif
#ifdef MPSS_BACKEND_NOOP
#include "mpss/impl/noop/noop_backend.h"
#endif
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <unordered_map>

namespace
{

std::string random_string(std::size_t length)
{
    // Note: This function is not cryptographically secure. It is only used for generating random key names for
    // probing algorithm support, so this is sufficient for our purposes.
    // NOLINTNEXTLINE(*-avoid-c-arrays) - char array initialized from string literal.
    static constexpr char chars[] = "0123456789"
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz";
    static constexpr std::size_t char_count = sizeof(chars) - 1;

    thread_local std::mt19937 rng{std::random_device{}()};
    thread_local std::uniform_int_distribution<std::size_t> dist(0, char_count - 1);

    std::string result(length, '\0');
    std::ranges::generate(result, [&] { return chars[dist(rng)]; });
    return result;
}

} // namespace

namespace mpss::impl
{

/**
 * @brief Friend-based accessor for setting KeyPair::backend_name_.
 *
 * KeyPair::backend_name_ is private with no public setter. BackendNameSetter is
 * declared as a friend of KeyPair, allowing the registry to stamp each key with
 * its backend name after creation or opening without exposing a public setter.
 */
class BackendNameSetter
{
  public:
    static void set(KeyPair &kp, const char *name)
    {
        kp.backend_name_ = name;
    }
};

// Maximum key name length. The YubiKey backend stores the name in an X.509 certificate's CN field.
// OpenSSL enforces the X.520 upper bound for Common Name (ub-common-name = 64), which limits the
// CN to 64 characters.
constexpr std::size_t max_key_name_length = 64;

namespace
{
// Validates a key name before it reaches any backend. Names are restricted to printable ASCII
// (0x20-0x7E). This rejects embedded NUL and other control bytes that would otherwise truncate at
// a C-string sink (CNG wide strings, Keychain CFString, JNI NewStringUTF, X.509 CN with len=-1) and
// alias one key onto another; it also avoids UTF-8 widening / Modified-UTF-8 ambiguity that would
// let the value seen by the API diverge from the value stored on the backend.
[[nodiscard]]
bool is_valid_key_name(std::string_view name)
{
    if (name.empty() || name.size() > max_key_name_length)
    {
        return false;
    }
    return std::ranges::all_of(name, [](char ch) {
        const auto uch = static_cast<unsigned char>(ch);
        return uch >= 0x20 && uch < 0x7F;
    });
}
} // namespace

/**
 * @brief Registry for managing multiple backend implementations.
 *
 * The registry installs the compiled-in backends and selects the default
 * backend based on environment variables or system defaults.
 * This class is an implementation detail and is not exposed in the public API.
 */
class BackendRegistry
{
  public:
    /**
     * @brief Get the singleton instance of the registry.
     */
    static BackendRegistry &Instance()
    {
        // Immortal singleton: heap-allocated once and never destroyed, so the registry outlives every
        // host static/global object -- including host statics whose destructors call into MPSS during
        // process exit. This avoids the static destruction-order fiasco (a host static destroyed after
        // the registry would otherwise touch a destroyed object). The one-time allocation is reclaimed
        // by the OS at process exit.
        static BackendRegistry &registry = *new BackendRegistry(); // NOLINT(cppcoreguidelines-owning-memory) -
                                                                   // intentional immortal singleton, never freed.
        return registry;
    }

    /**
     * @brief Get the default backend.
     * @return Pointer to the default backend, or nullptr if none is selected.
     */
    [[nodiscard]]
    std::shared_ptr<Backend> get_default_backend()
    {
        initialize_if_needed();

        if (nullptr == default_backend_)
        {
            utils::log_and_set_error("No default backend available.");
        }

        return default_backend_;
    }

    /**
     * @brief Get a backend by name.
     * @param[in] name The backend name.
     * @return Pointer to the backend, or nullptr if not found.
     */
    [[nodiscard]]
    std::shared_ptr<Backend> get_backend(std::string_view name)
    {
        initialize_if_needed();

        const std::string backend_name{name};
        const auto it = backends_.find(backend_name);
        if (backends_.end() != it)
        {
            return it->second;
        }

        return nullptr;
    }

    /**
     * @brief Get the names of all available (registered and usable) backends.
     * @return Vector of backend names.
     */
    [[nodiscard]]
    std::vector<const char *> get_available_backend_names()
    {
        initialize_if_needed();

        std::vector<const char *> names;
        names.reserve(backends_.size());
        for (const auto &[name, backend] : backends_)
        {
            names.push_back(backend->name());
        }
        return names;
    }

    /**
     * @brief Ensure backends are registered and the default backend is selected.
     */
    void initialize_if_needed()
    {
        if (init_attempted_.load(std::memory_order_acquire))
        {
            return;
        }

        std::scoped_lock lock{init_mutex_};
        if (init_attempted_.load(std::memory_order_relaxed))
        {
            return;
        }

        // Latch the attempt exactly once, on every exit path from the locked region. Registration and
        // backend selection then happen a single time; a persistently-bad MPSS_DEFAULT_BACKEND fails
        // closed (default_backend_ stays null) instead of re-running registration on every call. The
        // store cannot throw, so the ScopeGuard's terminate-on-exception path is unreachable.
        SCOPE_GUARD({ init_attempted_.store(true, std::memory_order_release); });

        // Register available backends.
#if defined(_WIN32) || defined(__APPLE__) || defined(__ANDROID__)
        install_builtin(std::make_shared<OSBackend>());
#endif
#ifdef MPSS_BACKEND_YUBIKEY
        install_builtin(std::make_shared<yubikey::YubiKeyBackend>());
#endif
#ifdef MPSS_BACKEND_NOOP
        // Registered but never chosen as the platform default: reaching it takes an explicit
        // backend name or MPSS_DEFAULT_BACKEND.
        install_builtin(std::make_shared<noop::NoopBackend>());
#endif

        // Check MPSS_DEFAULT_BACKEND environment variable.
        const char *env_backend = std::getenv("MPSS_DEFAULT_BACKEND"); // NOLINT(concurrency-mt-unsafe)
        if (nullptr != env_backend && std::strlen(env_backend) > 0)
        {
            const std::string requested{env_backend};
            const auto it = backends_.find(requested);
            if (backends_.end() != it)
            {
                default_backend_ = it->second;
                utils::log_warning("Default backend redirected to '{}' via MPSS_DEFAULT_BACKEND.", requested);
                return;
            }
            utils::log_and_set_error("Requested backend '{}' not found.", requested);
            return;
        }

        // Fall back to platform default.
        const char *default_name = platform_default_backend_name();
        if (nullptr != default_name)
        {
            const auto it = backends_.find(default_name);
            if (backends_.end() != it)
            {
                default_backend_ = it->second;
                utils::log_trace("Using default backend '{}'.", default_name);
                return;
            }
        }

        utils::log_and_set_error("No available backend found.");
    }

  private:
    BackendRegistry() = default;

    void install_builtin(std::shared_ptr<Backend> backend)
    {
        const std::string backend_name = backend->name();
        const bool inserted = backends_.try_emplace(backend_name, std::move(backend)).second;
        if (!inserted)
        {
            utils::log_and_set_error("Built-in backend '{}' was registered twice.", backend_name);
            return;
        }
        utils::log_trace("Registered backend '{}'.", backend_name);
    }

    std::unordered_map<std::string, std::shared_ptr<Backend>> backends_;
    std::shared_ptr<Backend> default_backend_;
    std::atomic<bool> init_attempted_{false};
    std::mutex init_mutex_;

    /**
     * @brief Get the platform-specific default backend name.
     */
    [[nodiscard]]
    const char *platform_default_backend_name() const
    {
#ifdef _WIN32
        return "os";
#elif defined(__APPLE__)
        return "os";
#elif defined(__ANDROID__)
        return "os";
#elif defined(__linux__) && defined(MPSS_BACKEND_YUBIKEY)
        // Linux: prefer YubiKey as it's the only available backend.
        return "yubikey";
#else
        return nullptr;
#endif
    }
};

bool is_algorithm_available(Algorithm algorithm, SecurityType min_security)
{
    const std::shared_ptr<Backend> backend = BackendRegistry::Instance().get_default_backend();
    if (nullptr == backend)
    {
        return false;
    }
    return backend->is_algorithm_available(algorithm, min_security);
}

bool is_algorithm_available(std::string_view backend_name, Algorithm algorithm, SecurityType min_security)
{
    const std::shared_ptr<Backend> backend = BackendRegistry::Instance().get_backend(backend_name);
    if (nullptr == backend)
    {
        utils::log_warning("Backend '{}' not found.", backend_name);
        return false;
    }
    return backend->is_algorithm_available(algorithm, min_security);
}

// Explicit-backend functions - the real implementations.
std::unique_ptr<KeyPair> create_key(std::string_view backend_name, std::string_view name, Algorithm algorithm,
                                    KeyPolicy policy, SecurityType min_security)
{
    if (!is_valid_key_name(name))
    {
        utils::log_warning("Invalid key name (must be 1-{} printable ASCII characters).", max_key_name_length);
        return nullptr;
    }

    BackendRegistry &registry = BackendRegistry::Instance();
    const std::shared_ptr<Backend> backend = registry.get_backend(backend_name);
    if (nullptr == backend)
    {
        utils::log_and_set_error("Backend '{}' not found.", backend_name);
        return nullptr;
    }

    utils::log_trace("Creating key '{}' with algorithm '{}' using backend '{}', minimum security '{}'.", name,
                     get_algorithm_info(algorithm).type_str, backend->name(), to_string(min_security));
    auto key = backend->create_key(name, algorithm, policy, min_security);
    if (nullptr == key)
    {
        return nullptr;
    }

    // Backends prune the mechanisms they attempt, but the postcondition is enforced here as well so
    // that it holds for every backend, including ones that do not implement pruning themselves. A
    // tier outside the defined range is treated as a failure rather than compared: an out-of-range
    // value would otherwise compare greater than every floor and be accepted.
    const SecurityType guaranteed = key->key_info().security_type;
    const bool valid_tier = is_valid_security_type(static_cast<std::uint8_t>(guaranteed));
    if (!valid_tier || !meets_minimum(guaranteed, min_security))
    {
        // A rejected key must never reach the caller, and must not be left behind. delete_key()
        // clears the last error, so the diagnostic is set after the attempt.
        const bool deleted = key->delete_key();
        if (!valid_tier)
        {
            utils::log_and_set_error(
                "Key '{}' created on backend '{}' reported an invalid security value {}. The key was {}.", name,
                backend->name(), static_cast<unsigned>(static_cast<std::uint8_t>(guaranteed)),
                deleted ? "deleted" : "NOT deleted; manual cleanup may be required");
            return nullptr;
        }
        if (deleted)
        {
            utils::log_and_set_error(
                "Key '{}' created on backend '{}' guarantees security '{}', below the required '{}'. The key was "
                "deleted.",
                name, backend->name(), to_string(guaranteed), to_string(min_security));
        }
        else
        {
            utils::log_and_set_error(
                "Key '{}' created on backend '{}' guarantees security '{}', below the required '{}', and could not be "
                "deleted. Manual cleanup may be required.",
                name, backend->name(), to_string(guaranteed), to_string(min_security));
        }
        return nullptr;
    }

    utils::log_trace("Key '{}' created on backend '{}' with security '{}'.", name, backend->name(),
                     to_string(guaranteed));
    BackendNameSetter::set(*key, backend->name());
    return key;
}

std::unique_ptr<KeyPair> open_key(std::string_view backend_name, std::string_view name, SecurityType min_security)
{
    if (!is_valid_key_name(name))
    {
        utils::log_warning("Invalid key name (must be 1-{} printable ASCII characters).", max_key_name_length);
        return nullptr;
    }

    BackendRegistry &registry = BackendRegistry::Instance();
    const std::shared_ptr<Backend> backend = registry.get_backend(backend_name);
    if (nullptr == backend)
    {
        utils::log_and_set_error("Backend '{}' not found.", backend_name);
        return nullptr;
    }

    utils::log_trace("Opening key '{}' using backend '{}', minimum security '{}'.", name, backend->name(),
                     to_string(min_security));
    auto key = backend->open_key(name, min_security);
    if (nullptr == key)
    {
        return nullptr;
    }

    const SecurityType guaranteed = key->key_info().security_type;
    if (!is_valid_security_type(static_cast<std::uint8_t>(guaranteed)))
    {
        utils::log_and_set_error("Key '{}' on backend '{}' reported an invalid security value {}.", name,
                                 backend->name(),
                                 static_cast<unsigned>(static_cast<std::uint8_t>(guaranteed)));
        return nullptr;
    }
    if (!meets_minimum(guaranteed, min_security))
    {
        utils::log_and_set_error(
            "Key '{}' on backend '{}' guarantees security '{}', below the required '{}'. The key was left intact.",
            name, backend->name(), to_string(guaranteed), to_string(min_security));
        // Returning here destroys the key pair, which releases the handle. An existing key is never
        // deleted just because the caller asked for a stronger guarantee than it can provide.
        return nullptr;
    }

    utils::log_trace("Key '{}' opened on backend '{}' with security '{}'.", name, backend->name(),
                     to_string(guaranteed));
    BackendNameSetter::set(*key, backend->name());
    return key;
}

bool verify(std::string_view backend_name, std::span<const std::byte> hash, std::span<const std::byte> public_key,
            Algorithm algorithm, std::span<const std::byte> sig)
{
    BackendRegistry &registry = BackendRegistry::Instance();
    const std::shared_ptr<Backend> backend = registry.get_backend(backend_name);
    if (nullptr == backend)
    {
        utils::log_and_set_error("Backend '{}' not found.", backend_name);
        return false;
    }

    return backend->verify(hash, public_key, algorithm, sig);
}

// Default-backend functions - delegate to the explicit-backend overloads.
std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                    SecurityType min_security)
{
    const std::shared_ptr<Backend> backend = BackendRegistry::Instance().get_default_backend();
    if (nullptr == backend)
    {
        utils::log_and_set_error("No default backend available for creating key '{}'.", name);
        return nullptr;
    }
    return create_key(backend->name(), name, algorithm, policy, min_security);
}

std::unique_ptr<KeyPair> open_key(std::string_view name, SecurityType min_security)
{
    const std::shared_ptr<Backend> backend = BackendRegistry::Instance().get_default_backend();
    if (nullptr == backend)
    {
        utils::log_and_set_error("No default backend available for opening key '{}'.", name);
        return nullptr;
    }
    return open_key(backend->name(), name, min_security);
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    const std::shared_ptr<Backend> backend = BackendRegistry::Instance().get_default_backend();
    if (nullptr == backend)
    {
        utils::log_and_set_error("No default backend available for verification.");
        return false;
    }
    return verify(backend->name(), hash, public_key, algorithm, sig);
}

// Discovery functions.
std::vector<const char *> get_available_backends()
{
    return BackendRegistry::Instance().get_available_backend_names();
}

const char *get_default_backend_name()
{
    BackendRegistry &registry = BackendRegistry::Instance();
    const std::shared_ptr<Backend> active = registry.get_default_backend();
    if (nullptr != active)
    {
        return active->name();
    }
    return "";
}

bool Backend::is_algorithm_available(Algorithm algorithm, SecurityType min_security) const
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        return false;
    }

    // Sample a random name for a key and try creating it at the requested floor.
    const std::string random_key = "MPSS_TEST_KEY_" + random_string(16) + "_CAN_DELETE";
    std::unique_ptr<KeyPair> key = create_key(random_key, algorithm, KeyPolicy::none, min_security);

    // Could we even create a key?
    if (nullptr == key)
    {
        return false;
    }
    SCOPE_GUARD({
        // Delete the key if it was created.
        const bool key_deleted = key->delete_key();
        if (!key_deleted)
        {
            utils::log_and_set_error("Created key '{}' could not be deleted.", random_key);
        }
    });

    // The probe calls the backend directly, so it repeats the floor postcondition the registry
    // applies to create_key. The scope guard above deletes the probe key either way.
    const SecurityType guaranteed = key->key_info().security_type;
    if (!meets_minimum(guaranteed, min_security))
    {
        utils::log_trace("Probe key '{}' guarantees security '{}', below the required '{}'.", random_key,
                         to_string(guaranteed), to_string(min_security));
        return false;
    }

    // Create some data and sign.
    const std::vector<std::byte> hash(info.hash_bits / 8, static_cast<std::byte>('a'));
    const std::size_t sig_size = key->sign_hash(hash, {});
    if (0 == sig_size)
    {
        return false;
    }

    std::vector<std::byte> sig(sig_size);
    const std::size_t written = key->sign_hash(hash, sig);
    return 0 != written;
}

} // namespace mpss::impl
