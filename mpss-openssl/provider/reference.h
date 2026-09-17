// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/utils.h"
#include <mpss/key_info.h>
#include <span>
#include <string>
#include <string_view>

namespace mpss_openssl::provider
{

// A key reference is a load reference PEM-wrapped under this label.
inline constexpr const char *mpss_key_reference_pem_label = "MPSS KEY REFERENCE";

// Carries a store minimum across its synchronous object callback without changing reference bytes.
class mpss_key_load_isolation_scope
{
  public:
    explicit mpss_key_load_isolation_scope(mpss::IsolationLevel minimum_isolation) noexcept;
    ~mpss_key_load_isolation_scope() noexcept;

    mpss_key_load_isolation_scope(const mpss_key_load_isolation_scope &) = delete;
    mpss_key_load_isolation_scope &operator=(const mpss_key_load_isolation_scope &) = delete;

  private:
    mpss::IsolationLevel previous_;
};

[[nodiscard]]
mpss::IsolationLevel mpss_key_load_minimum_isolation() noexcept;

// The "load reference" is the opaque byte blob handed to mpss_keymgmt_load via
// OSSL_OBJECT_PARAM_REFERENCE. It packs the target backend and key name as "<backend>\0<key_name>";
// an empty backend selects the default backend. The single NUL separates the two fields, which is
// unambiguous because neither a backend nor a key name may contain an embedded NUL. These functions
// guarantee only that the blob splits unambiguously into a non-empty name and a backend; whether
// either value is acceptable is decided when the key is opened.
[[nodiscard]]
bool mpss_build_key_load_reference(std::string_view backend, std::string_view key_name, utils::byte_vector &reference);

[[nodiscard]]
bool mpss_parse_key_load_reference(std::span<const unsigned char> reference, std::string &backend,
                                   std::string &key_name);

} // namespace mpss_openssl::provider
