// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/windows/crypto_params.h"
#include "mpss/mpss.h"

#include <string>
#include <string_view>

namespace mpss::impl::os::utils
{

crypto_params const *get_crypto_params(Algorithm algorithm) noexcept;

// Converts a wide string from a Windows API to UTF-8 so it can be logged. Returns an empty string
// when the input is empty or cannot be converted.
[[nodiscard]]
std::string wide_to_utf8(std::wstring_view value);

std::size_t decode_raw_signature(std::span<const std::byte> der_sig, Algorithm algorithm,
                                 std::span<std::byte> raw_sig) noexcept;

} // namespace mpss::impl::os::utils
