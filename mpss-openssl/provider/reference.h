// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/defines.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/utils/utils.h"
#include <cstddef>
#include <span>
#include <string_view>

namespace mpss_openssl::provider
{

inline constexpr const char *mpss_key_reference_structure = "MpssKeyReference";
inline constexpr const char *mpss_key_reference_pem_label = "MPSS KEY REFERENCE";

// A key reference is the persisted key's name, PEM-wrapped under mpss_key_reference_pem_label so a
// caller can reopen the key later. The body is exactly the UTF-8 key name; the PEM label identifies
// the format (a future layout would use a new label). mpss reopens the key by name and the backend
// holds the actual key material.
inline constexpr std::size_t mpss_key_reference_max_name_len = 64;
// Upper bound on an encoded reference PEM: the name is base64-inflated (~4/3) with label lines and
// newline wrapping, so twice the name cap plus a fixed slack bounds it and lets readers cap input.
inline constexpr std::size_t mpss_key_reference_max_encoded_size = 2 * mpss_key_reference_max_name_len + 256;

[[nodiscard]]
MPSS_OPENSSL_DECOR bool mpss_build_key_reference_body(std::string_view key_name, utils::byte_vector &body);

[[nodiscard]]
MPSS_OPENSSL_DECOR bool mpss_parse_key_reference_body(std::span<const unsigned char> body,
                                                      mpss_key_reference &key_reference);

} // namespace mpss_openssl::provider
