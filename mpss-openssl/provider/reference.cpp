// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/reference.h"
#include <algorithm>
#include <cstddef>
#include <mpss/utils/utilities.h>
#include <span>

namespace mpss_openssl::provider
{

[[nodiscard]]
bool mpss_build_key_reference_body(std::string_view key_name, utils::byte_vector &body)
{
    if (key_name.empty() || key_name.size() > mpss_key_reference_max_name_len)
    {
        mpss::utils::log_warning("mpss key reference: refusing to build; name length {} is out of range",
                                 key_name.size());
        return false;
    }
    if (key_name.find('\0') != std::string_view::npos)
    {
        mpss::utils::log_warning("mpss key reference: refusing to build; name contains an embedded NUL");
        return false;
    }

    const auto name_bytes = std::as_bytes(std::span<const char>{key_name.data(), key_name.size()});
    body.assign(name_bytes.begin(), name_bytes.end());
    return true;
}

[[nodiscard]]
bool mpss_parse_key_reference_body(std::span<const unsigned char> body, mpss_key_reference &key_reference)
{
    if (body.empty() || body.size() > mpss_key_reference_max_name_len)
    {
        mpss::utils::log_warning("mpss key reference: rejecting body with out-of-range name length {}", body.size());
        return false;
    }
    if (std::find(body.begin(), body.end(), static_cast<unsigned char>('\0')) != body.end())
    {
        mpss::utils::log_warning("mpss key reference: rejecting body with an embedded NUL in the name");
        return false;
    }

    key_reference.key_name.assign(reinterpret_cast<const char *>(body.data()), body.size());
    return true;
}

} // namespace mpss_openssl::provider
