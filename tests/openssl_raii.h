// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/utils.h"
#include <memory>
#include <openssl/bio.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>

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

struct encoder_ctx_deleter
{
    void operator()(OSSL_ENCODER_CTX *ctx) const noexcept
    {
        OSSL_ENCODER_CTX_free(ctx);
    }
};

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;
// Reuse the provider's BIO deleter rather than defining a second one.
using bio_ptr = utils::bio_ptr;
using encoder_ctx_ptr = std::unique_ptr<OSSL_ENCODER_CTX, encoder_ctx_deleter>;

} // namespace mpss_openssl::testing
