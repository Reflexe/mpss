// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "mpss-openssl/utils/names.h"
#include <memory>
#include <mpss/mpss.h>
#include <mpss/security_type.h>
#include <mutex>
#include <string>
#include <type_traits>
#include <vector>

// The C mirror in api.h and the C++ enum must agree exactly: the "security_type" key parameter is
// reported as a raw ordinal, so a divergence would silently mislabel a key's guarantee.
static_assert(static_cast<std::underlying_type_t<mpss::SecurityType>>(mpss::SecurityType::software) ==
              MPSS_SECURITY_TYPE_SOFTWARE);
static_assert(static_cast<std::underlying_type_t<mpss::SecurityType>>(mpss::SecurityType::mixed) ==
              MPSS_SECURITY_TYPE_MIXED);
static_assert(static_cast<std::underlying_type_t<mpss::SecurityType>>(mpss::SecurityType::hardware) ==
              MPSS_SECURITY_TYPE_HARDWARE);
static_assert(static_cast<std::underlying_type_t<mpss::SecurityType>>(mpss::SecurityType::secure_element) ==
              MPSS_SECURITY_TYPE_SECURE_ELEMENT);
static_assert(mpss::max_security_type_value == MPSS_SECURITY_TYPE_SECURE_ELEMENT,
              "A new SecurityType value must also be mirrored in mpss_security_type_t.");

bool mpss_delete_key(const char *key_name)
{
    if (nullptr == key_name)
    {
        return false;
    }

    // Try to open the key.
    const std::unique_ptr<mpss::KeyPair> key_pair = mpss::KeyPair::Open(key_name);
    if (nullptr == key_pair)
    {
        return false;
    }

    // Delete the key.
    if (!key_pair->delete_key())
    {
        return false;
    }

    return true;
}

bool mpss_delete_key_from_backend(const char *key_name, const char *backend_name)
{
    if (nullptr == key_name || nullptr == backend_name)
    {
        return false;
    }

    // Try to open the key from the specified backend.
    const std::unique_ptr<mpss::KeyPair> key_pair = mpss::KeyPair::Open(key_name, backend_name);
    if (nullptr == key_pair)
    {
        return false;
    }

    // Delete the key.
    return key_pair->delete_key();
}

bool mpss_is_algorithm_available(const char *algorithm_name)
{
    if (nullptr == algorithm_name)
    {
        return false;
    }
    const mpss::Algorithm algorithm = mpss_openssl::utils::try_get_mpss_algorithm(algorithm_name);
    if (mpss::Algorithm::unsupported == algorithm)
    {
        return false;
    }
    return mpss::is_algorithm_available(algorithm);
}

bool mpss_is_algorithm_available_in_backend(const char *algorithm_name, const char *backend_name)
{
    if (nullptr == algorithm_name || nullptr == backend_name)
    {
        return false;
    }
    const mpss::Algorithm algorithm = mpss_openssl::utils::try_get_mpss_algorithm(algorithm_name);
    if (mpss::Algorithm::unsupported == algorithm)
    {
        return false;
    }
    return mpss::is_algorithm_available(algorithm, backend_name);
}

const char **mpss_get_available_algorithms()
{
    // Build a static null-terminated array of string pointers on first call.
    // The algorithm name strings are compile-time constants, so no ownership issues.
    static std::vector<const char *> cache;
    static std::once_flag flag;
    std::call_once(flag, []() {
        for (const mpss::Algorithm &alg : mpss::get_available_algorithms())
        {
            cache.push_back(mpss::get_algorithm_info(alg).type_str);
        }
        cache.push_back(nullptr); // null-terminate
    });
    return cache.data();
}

const char *mpss_get_error()
{
    // Use thread-local storage to hold a copy of the last std::string.
    static thread_local std::string last_error_str;

    last_error_str = mpss::get_error(); // Update buffer
    return last_error_str.c_str();
}

const char **mpss_get_available_backends()
{
    // Build a static null-terminated array of string pointers on first call.
    // Backend availability is determined at compile time, so it won't change.
    static std::vector<const char *> ptrs;
    static std::once_flag flag;
    std::call_once(flag, []() {
        ptrs = mpss::get_available_backends();
        ptrs.push_back(nullptr); // null-terminate
    });
    return ptrs.data();
}

const char *mpss_get_default_backend_name()
{
    return mpss::get_default_backend_name();
}
