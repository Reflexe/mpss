// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <openssl/evp.h>
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

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using X509ReqPtr = std::unique_ptr<X509_REQ, X509ReqDeleter>;

} // namespace mpss_openssl::testing
