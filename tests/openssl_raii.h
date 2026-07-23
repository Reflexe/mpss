// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <openssl/bio.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace mpss_openssl::testing
{

struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY *key) const noexcept
    {
        EVP_PKEY_free(key);
    }
};

struct EvpPkeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX *ctx) const noexcept
    {
        EVP_PKEY_CTX_free(ctx);
    }
};

struct X509ReqDeleter
{
    void operator()(X509_REQ *req) const noexcept
    {
        X509_REQ_free(req);
    }
};

struct X509Deleter
{
    void operator()(X509 *cert) const noexcept
    {
        X509_free(cert);
    }
};

struct BioDeleter
{
    void operator()(BIO *bio) const noexcept
    {
        BIO_free(bio);
    }
};

struct SslCtxDeleter
{
    void operator()(SSL_CTX *ctx) const noexcept
    {
        SSL_CTX_free(ctx);
    }
};

struct SslDeleter
{
    void operator()(SSL *ssl) const noexcept
    {
        SSL_free(ssl);
    }
};

struct EncoderCtxDeleter
{
    void operator()(OSSL_ENCODER_CTX *ctx) const noexcept
    {
        OSSL_ENCODER_CTX_free(ctx);
    }
};

struct EvpMdDeleter
{
    void operator()(EVP_MD *md) const noexcept
    {
        EVP_MD_free(md);
    }
};

struct OsslProviderDeleter
{
    void operator()(OSSL_PROVIDER *prov) const noexcept
    {
        OSSL_PROVIDER_unload(prov);
    }
};

struct OsslLibCtxDeleter
{
    void operator()(OSSL_LIB_CTX *libctx) const noexcept
    {
        OSSL_LIB_CTX_free(libctx);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using X509ReqPtr = std::unique_ptr<X509_REQ, X509ReqDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using EncoderCtxPtr = std::unique_ptr<OSSL_ENCODER_CTX, EncoderCtxDeleter>;
using EvpMdPtr = std::unique_ptr<EVP_MD, EvpMdDeleter>;
using OsslProviderPtr = std::unique_ptr<OSSL_PROVIDER, OsslProviderDeleter>;
using OsslLibCtxPtr = std::unique_ptr<OSSL_LIB_CTX, OsslLibCtxDeleter>;

} // namespace mpss_openssl::testing
