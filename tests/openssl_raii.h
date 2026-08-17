// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/ossl_ptr.h"
#include <openssl/encoder.h>

namespace mpss_openssl::testing
{

// Reuse the provider's smart pointers rather than defining a second set.
using bio_ptr = utils::bio_ptr;
using evp_pkey_ptr = utils::evp_pkey_ptr;
using evp_pkey_ctx_ptr = utils::evp_pkey_ctx_ptr;
using encoder_ctx_ptr = utils::ossl_ptr<OSSL_ENCODER_CTX, OSSL_ENCODER_CTX_free>;

} // namespace mpss_openssl::testing
