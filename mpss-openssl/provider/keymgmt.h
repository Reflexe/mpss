// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <mpss/mpss.h>
#include <openssl/core.h>
#include <openssl/types.h>
#include <optional>
#include <string>
#include <string_view>

namespace mpss_openssl::provider
{

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

struct mpss_key
{
    std::unique_ptr<mpss::KeyPair> key_pair = nullptr;
    std::optional<std::string> name = std::nullopt;
    std::optional<std::string> mpss_algorithm = std::nullopt;
    std::optional<std::string> mpss_backend = std::nullopt;
    std::optional<std::string> sig_name = std::nullopt;
    std::optional<std::string> group_name = std::nullopt;
    std::optional<std::string> hash_name = std::nullopt;
    std::optional<std::string> alg_name = std::nullopt;

    mpss_key(std::string_view key_name, std::optional<std::string> &mpss_algorithm,
             const std::optional<std::string> &mpss_backend, mpss::KeyPolicy creation_policy = mpss::KeyPolicy::none,
             mpss::IsolationLevel minimum_isolation = mpss::IsolationLevel::unspecified);

    ~mpss_key() = default;

    [[nodiscard]]
    bool has_valid_key() const noexcept;
};

extern const OSSL_ALGORITHM mpss_keymgmt_algorithms[];

int mpss_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg);

} // namespace mpss_openssl::provider
