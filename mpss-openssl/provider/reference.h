// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/defines.h"
#include "mpss-openssl/utils/utils.h"
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace mpss_openssl::provider
{

// Longest key name a reference may carry. Matches mpss's own key name limit, so no name the backend
// would accept is rejected here.
inline constexpr std::size_t mpss_key_reference_max_name_len = 64;

// The "load reference" is the opaque byte blob handed to mpss_keymgmt_load via
// OSSL_OBJECT_PARAM_REFERENCE. It packs the target backend and key name as "<backend>\0<key_name>";
// an empty backend selects the default backend. The first NUL separates the two fields, which is
// unambiguous because neither a backend nor a key name may contain an embedded NUL. Build fails for
// a key name that is empty or longer than mpss_key_reference_max_name_len, or for a NUL inside
// either field; parse fails for a blob with no separator or with an out-of-range key name length.
[[nodiscard]]
MPSS_OPENSSL_DECOR bool mpss_build_key_load_reference(std::string_view backend, std::string_view key_name,
                                                      utils::byte_vector &reference);

[[nodiscard]]
MPSS_OPENSSL_DECOR bool mpss_parse_key_load_reference(std::span<const unsigned char> reference,
                                                      std::string &backend, std::string &key_name);

} // namespace mpss_openssl::provider
