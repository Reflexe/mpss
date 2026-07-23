// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <memory>
#include <openssl/evp.h>
#include <string_view>
#include <vector>

namespace mpss::tests::mock_pki
{

using EvpKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

/**
 * @brief A generated EC P-256 key with its DER SubjectPublicKeyInfo.
 *
 * Test-only OpenSSL "test CA" material; not real per-platform evidence generation.
 */
struct TestKey
{
    EvpKeyPtr pkey{nullptr, EVP_PKEY_free};
    std::vector<std::byte> spki_der;

    [[nodiscard]]
    bool valid() const
    {
        return nullptr != pkey && !spki_der.empty();
    }
};

/**
 * @brief A DER-encoded X.509 certificate.
 */
struct TestCert
{
    std::vector<std::byte> der;

    [[nodiscard]]
    bool valid() const
    {
        return !der.empty();
    }
};

/**
 * @brief Generate a fresh EC P-256 key pair.
 */
[[nodiscard]]
TestKey generate_ec_key();

/**
 * @brief Create a self-signed root CA certificate for @p key.
 */
[[nodiscard]]
TestCert create_root(const TestKey &key, std::string_view common_name);

/**
 * @brief Create a leaf certificate for @p subject signed by @p issuer_key / @p issuer_cert.
 */
[[nodiscard]]
TestCert create_leaf(const TestKey &subject, const TestKey &issuer_key, const TestCert &issuer_cert,
                     std::string_view common_name);

} // namespace mpss::tests::mock_pki
