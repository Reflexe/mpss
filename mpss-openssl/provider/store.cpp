// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/store.h"
#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/names.h"
#include "mpss-openssl/utils/utils.h"
#include <cstddef>
#include <memory>
#include <mpss/mpss.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <string>
#include <string_view>

namespace mpss_openssl::provider
{

// Loader context for a single "mpss:<key_name>" store URI. The named key is surfaced as exactly one
// object; loaded tracks whether that object has already been delivered. backend is the optional
// target backend set via the mpss_backend ctx param (empty means the default backend).
struct mpss_store_ctx
{
    std::string key_name;
    std::string backend;
    bool loaded = false;
};

} // namespace mpss_openssl::provider

namespace
{

using namespace ::mpss_openssl::provider;
using namespace ::mpss_openssl::utils;

// The URI scheme this loader handles: OSSL_STORE_open("mpss:<key_name>", ...).
constexpr std::string_view mpss_store_scheme = "mpss:";

extern "C" void *mpss_store_open([[maybe_unused]] void *provctx, const char *uri)
{
    if (nullptr == uri)
    {
        return nullptr;
    }

    const std::string_view uri_sv{uri};
    if (!uri_sv.starts_with(mpss_store_scheme))
    {
        return nullptr;
    }

    const std::string_view key_name = uri_sv.substr(mpss_store_scheme.size());
    if (key_name.empty())
    {
        return nullptr;
    }

    mpss_store_ctx *ctx = mpss_new<mpss_store_ctx>();
    if (nullptr == ctx)
    {
        return nullptr;
    }
    ctx->key_name = key_name;

    return ctx;
}

extern "C" int mpss_store_load(void *loaderctx, OSSL_CALLBACK *object_cb, void *object_cbarg,
                               [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK *pw_cb, [[maybe_unused]] void *pw_cbarg)
{
    mpss_store_ctx *ctx = static_cast<mpss_store_ctx *>(loaderctx);
    if (nullptr == ctx || nullptr == object_cb)
    {
        return 0;
    }

    // Only one object is ever surfaced for a given name. Mark it consumed before delivery so the
    // caller's load/eof loop terminates regardless of whether delivery succeeds.
    if (ctx->loaded)
    {
        return 0;
    }
    ctx->loaded = true;

    // Key management (mpss_keymgmt_load) builds the actual key object, but it runs as a separate
    // provider operation and receives only an opaque byte "reference" -- it has no access to this
    // loader context. That reference is the sole channel for telling it which key to open, so pack the
    // target backend and key name into it (see mpss_build_key_load_reference). The blob only needs to
    // outlive the synchronous object callback below, so a local is sufficient.
    byte_vector reference;
    if (!mpss_build_key_load_reference(ctx->backend, ctx->key_name, reference))
    {
        return 0;
    }

    // The key material never leaves the backend, so we surface a reference object rather than key
    // data. OpenSSL fetches the key management named by the data type (matched to the mpss provider
    // via the caller's property query) and hands it this reference to build the EVP_PKEY. The data
    // type must be a name that key management is registered under.
    int object_type = OSSL_OBJECT_PKEY;

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    // const_cast: OSSL_PARAM_construct_utf8_string takes a non-const char*; the string is not
    // modified.
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, const_cast<char *>(ec_data_type), 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, reference.data(), reference.size());
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
}

extern "C" const OSSL_PARAM *mpss_store_settable_ctx_params([[maybe_unused]] void *provctx)
{
    static const OSSL_PARAM settable[] = {OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, nullptr),
                                          OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, nullptr, 0),
                                          OSSL_PARAM_utf8_string("mpss_backend", nullptr, 0), OSSL_PARAM_END};
    return settable;
}

extern "C" int mpss_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    mpss_store_ctx *ctx = static_cast<mpss_store_ctx *>(loaderctx);
    if (nullptr == ctx)
    {
        return 0;
    }

    // Optional mpss_backend selects which backend the key is opened from (symmetric with the
    // mpss_backend key-generation parameter). If absent, the default backend is used.
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "mpss_backend");
    if (nullptr != p)
    {
        const char *value_str = nullptr;
        // OSSL_PARAM_get_utf8_string_ptr returns success with *value_str == nullptr for a NULL-data
        // param, so guard before assigning into std::string (operator=(nullptr) is UB via strlen).
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &value_str) || nullptr == value_str)
        {
            return 0;
        }
        ctx->backend = value_str;
    }

    // OpenSSL also forwards the caller's property query and expected-object-type hint here; it
    // handles both itself (key management is fetched with that property query, and the result is
    // filtered against the expected type), so those are accepted without further action.
    return 1;
}

extern "C" int mpss_store_eof(void *loaderctx)
{
    const mpss_store_ctx *ctx = static_cast<const mpss_store_ctx *>(loaderctx);

    // Report end-of-data once the single object has been delivered (or if the context is missing).
    if (nullptr == ctx)
    {
        return 1;
    }
    return ctx->loaded ? 1 : 0;
}

extern "C" int mpss_store_close(void *loaderctx)
{
    mpss_delete(static_cast<mpss_store_ctx *>(loaderctx));
    return 1;
}

extern "C" int mpss_store_delete([[maybe_unused]] void *provctx, const char *uri, const OSSL_PARAM params[],
                                 [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK *pw_cb, [[maybe_unused]] void *pw_cbarg)
{
    // Delete is a standalone operation: it receives the URI and parameters directly (no store_open),
    // so it parses the "mpss:<key_name>" URI the same way store_open does.
    if (nullptr == uri)
    {
        return 0;
    }
    const std::string_view uri_sv{uri};
    if (!uri_sv.starts_with(mpss_store_scheme))
    {
        return 0;
    }
    const std::string_view key_name = uri_sv.substr(mpss_store_scheme.size());
    if (key_name.empty())
    {
        return 0;
    }

    // Optional mpss_backend selects which backend the key is deleted from (as in the open path).
    std::string backend;
    const OSSL_PARAM *p = (nullptr != params) ? OSSL_PARAM_locate_const(params, "mpss_backend") : nullptr;
    if (nullptr != p)
    {
        const char *value_str = nullptr;
        // OSSL_PARAM_get_utf8_string_ptr returns success with *value_str == nullptr for a NULL-data
        // param, so guard before assigning into std::string (operator=(nullptr) is UB via strlen).
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &value_str) || nullptr == value_str)
        {
            return 0;
        }
        backend = value_str;
    }

    // Open the key (default backend when none is given) and delete it. A missing key or a failed
    // deletion reports failure.
    const std::unique_ptr<mpss::KeyPair> key =
        backend.empty() ? mpss::KeyPair::Open(key_name) : mpss::KeyPair::Open(key_name, backend);
    if (nullptr == key)
    {
        return 0;
    }
    return key->delete_key() ? 1 : 0;
}

const OSSL_DISPATCH mpss_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, reinterpret_cast<void (*)(void)>(mpss_store_open)},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, reinterpret_cast<void (*)(void)>(mpss_store_settable_ctx_params)},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS, reinterpret_cast<void (*)(void)>(mpss_store_set_ctx_params)},
    {OSSL_FUNC_STORE_LOAD, reinterpret_cast<void (*)(void)>(mpss_store_load)},
    {OSSL_FUNC_STORE_EOF, reinterpret_cast<void (*)(void)>(mpss_store_eof)},
    {OSSL_FUNC_STORE_CLOSE, reinterpret_cast<void (*)(void)>(mpss_store_close)},
    {OSSL_FUNC_STORE_DELETE, reinterpret_cast<void (*)(void)>(mpss_store_delete)},
    OSSL_DISPATCH_END};

} // namespace

namespace mpss_openssl::provider
{

const OSSL_ALGORITHM mpss_store_algorithms[] = {{"mpss", "provider=mpss", mpss_store_functions, "mpss key store"},
                                                {nullptr, nullptr, nullptr, nullptr}};

} // namespace mpss_openssl::provider
