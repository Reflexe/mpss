// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/reference.h"
#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace mpss_openssl::provider
{

bool mpss_build_key_load_reference(std::string_view backend, std::string_view key_name, utils::byte_vector &reference)
{
    if (key_name.empty())
    {
        return false;
    }
    if (std::string_view::npos != backend.find('\0') || std::string_view::npos != key_name.find('\0'))
    {
        return false;
    }

    reference.clear();
    reference.reserve(backend.size() + 1 + key_name.size());
    const auto backend_bytes = std::as_bytes(std::span<const char>{backend});
    reference.insert(reference.end(), backend_bytes.begin(), backend_bytes.end());
    reference.push_back(std::byte{0});
    const auto name_bytes = std::as_bytes(std::span<const char>{key_name});
    reference.insert(reference.end(), name_bytes.begin(), name_bytes.end());

    return true;
}

bool mpss_parse_key_load_reference(std::span<const unsigned char> reference, std::string &backend,
                                   std::string &key_name)
{
    const auto sep = std::ranges::find(reference, static_cast<unsigned char>('\0'));
    if (sep == reference.end())
    {
        return false;
    }

    // A second NUL would make the split ambiguous, so the blob is not one this codec produced.
    if (std::ranges::find(sep + 1, reference.end(), static_cast<unsigned char>('\0')) != reference.end())
    {
        return false;
    }

    const std::size_t sep_index = static_cast<std::size_t>(sep - reference.begin());
    const std::size_t name_size = reference.size() - sep_index - 1;
    if (0 == name_size)
    {
        return false;
    }

    const char *const bytes = reinterpret_cast<const char *>(reference.data());
    backend.assign(bytes, sep_index);
    key_name.assign(bytes + sep_index + 1, name_size);

    return true;
}

} // namespace mpss_openssl::provider
