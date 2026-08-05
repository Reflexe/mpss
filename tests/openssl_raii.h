// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/utils.h"
#include <memory>
#include <openssl/bio.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace mpss_openssl::testing
{

struct evp_pkey_deleter
{
    void operator()(EVP_PKEY *key) const noexcept
    {
        EVP_PKEY_free(key);
    }
};

struct evp_pkey_ctx_deleter
{
    void operator()(EVP_PKEY_CTX *ctx) const noexcept
    {
        EVP_PKEY_CTX_free(ctx);
    }
};

struct x509_req_deleter
{
    void operator()(X509_REQ *req) const noexcept
    {
        X509_REQ_free(req);
    }
};

struct x509_deleter
{
    void operator()(X509 *cert) const noexcept
    {
        X509_free(cert);
    }
};

struct ssl_ctx_deleter
{
    void operator()(SSL_CTX *ctx) const noexcept
    {
        SSL_CTX_free(ctx);
    }
};

struct ssl_deleter
{
    void operator()(SSL *ssl) const noexcept
    {
        SSL_free(ssl);
    }
};

struct encoder_ctx_deleter
{
    void operator()(OSSL_ENCODER_CTX *ctx) const noexcept
    {
        OSSL_ENCODER_CTX_free(ctx);
    }
};

struct evp_md_deleter
{
    void operator()(EVP_MD *md) const noexcept
    {
        EVP_MD_free(md);
    }
};

struct ossl_provider_deleter
{
    void operator()(OSSL_PROVIDER *prov) const noexcept
    {
        OSSL_PROVIDER_unload(prov);
    }
};

struct ossl_lib_ctx_deleter
{
    void operator()(OSSL_LIB_CTX *libctx) const noexcept
    {
        OSSL_LIB_CTX_free(libctx);
    }
};

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;
using x509_req_ptr = std::unique_ptr<X509_REQ, x509_req_deleter>;
using x509_ptr = std::unique_ptr<X509, x509_deleter>;
// Reuse the provider's BIO deleter rather than defining a second one.
using bio_ptr = utils::bio_ptr;
using ssl_ctx_ptr = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;
using ssl_ptr = std::unique_ptr<SSL, ssl_deleter>;
using encoder_ctx_ptr = std::unique_ptr<OSSL_ENCODER_CTX, encoder_ctx_deleter>;
using evp_md_ptr = std::unique_ptr<EVP_MD, evp_md_deleter>;
using ossl_provider_ptr = std::unique_ptr<OSSL_PROVIDER, ossl_provider_deleter>;
using ossl_lib_ctx_ptr = std::unique_ptr<OSSL_LIB_CTX, ossl_lib_ctx_deleter>;

} // namespace mpss_openssl::testing
