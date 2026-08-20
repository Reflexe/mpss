// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/utils.h"
#include <memory>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace mpss_openssl::utils
{

/** @brief Gives the `OPENSSL_free` macro a name that can be used as a template argument. */
inline void openssl_free_fn(void *ptr) noexcept
{
    OPENSSL_free(ptr);
}

/**
 * @brief Owns a buffer that OpenSSL allocated, such as the output of an `i2d_*` call.
 *
 * Released with `OPENSSL_free`, not `delete`.
 */
template <typename T> using openssl_buf_ptr = std::unique_ptr<T, fn_deleter<openssl_free_fn>>;

/**
 * @brief Owns a BIO, or a whole BIO chain.
 *
 * `BIO_free_all` rather than `BIO_free`: the two are identical for an unchained BIO, and for a chain
 * built with `BIO_push` only `BIO_free_all` is correct, since `BIO_free` releases the head and
 * silently leaks everything below it.
 */
using bio_ptr = std::unique_ptr<BIO, fn_deleter<BIO_free_all>>;

/** @brief Owns an EVP_PKEY. */
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, fn_deleter<EVP_PKEY_free>>;

/** @brief Owns an EVP_PKEY_CTX. */
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, fn_deleter<EVP_PKEY_CTX_free>>;

} // namespace mpss_openssl::utils
