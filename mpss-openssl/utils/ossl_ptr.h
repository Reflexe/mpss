// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace mpss_openssl::utils
{

/**
 * @brief Deleter that releases an object with a compile-time known function.
 *
 * @p Fn is a template parameter rather than a stored function pointer, so the deleter is an empty
 * class and a `std::unique_ptr` using it stays the size of a raw pointer.
 */
template <auto Fn> struct fn_deleter
{
    template <typename T> void operator()(T *ptr) const noexcept
    {
        Fn(ptr);
    }
};

/**
 * @brief A `std::unique_ptr` that releases its object with @p Fn.
 *
 * A new owning type is one alias, for example:
 * @code
 * using x509_ptr = ossl_ptr<X509, X509_free>;
 * @endcode
 * @p Fn must be a function, not a macro. `OPENSSL_free` is a macro; see @ref openssl_ptr.
 */
template <typename T, auto Fn> using ossl_ptr = std::unique_ptr<T, fn_deleter<Fn>>;

/** @brief Gives the `OPENSSL_free` macro a name that can be used as a template argument. */
inline void openssl_free_fn(void *ptr) noexcept
{
    OPENSSL_free(ptr);
}

/** @brief Owns a buffer that OpenSSL allocated, such as the output of an `i2d_*` call. */
template <typename T> using openssl_ptr = ossl_ptr<T, openssl_free_fn>;

/**
 * @brief Owns a BIO, or a whole BIO chain.
 *
 * `BIO_free_all` rather than `BIO_free`: the two are identical for an unchained BIO, and for a chain
 * built with `BIO_push` only `BIO_free_all` is correct, since `BIO_free` releases the head and
 * silently leaks everything below it.
 */
using bio_ptr = ossl_ptr<BIO, BIO_free_all>;

/** @brief Owns an EVP_PKEY. */
using evp_pkey_ptr = ossl_ptr<EVP_PKEY, EVP_PKEY_free>;

/** @brief Owns an EVP_PKEY_CTX. */
using evp_pkey_ctx_ptr = ossl_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;

} // namespace mpss_openssl::utils
