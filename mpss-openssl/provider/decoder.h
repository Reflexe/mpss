// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <openssl/core.h>
#include <openssl/types.h>

namespace mpss_openssl::provider
{

struct mpss_decoder_ctx
{
    const OSSL_CORE_HANDLE *handle{nullptr};
    OSSL_LIB_CTX *libctx{nullptr};
};

extern const OSSL_ALGORITHM mpss_decoder_algorithms[];

} // namespace mpss_openssl::provider
