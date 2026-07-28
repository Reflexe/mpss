// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/utils/utils.h"
#include <memory>
#include <mpss/mpss.h>
#include <string_view>

namespace mpss_openssl::utils
{

using namespace mpss;

bool delete_key(std::string_view name)
{
    const std::unique_ptr<KeyPair> key_pair = KeyPair::Open(name);
    return nullptr != key_pair && key_pair->delete_key();
}

bool delete_key(std::string_view name, std::string_view backend_name)
{
    const std::unique_ptr<KeyPair> key_pair = KeyPair::Open(name, backend_name);
    return nullptr != key_pair && key_pair->delete_key();
}

} // namespace mpss_openssl::utils
