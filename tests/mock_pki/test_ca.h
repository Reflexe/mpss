// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <openssl/evp.h>
#include <span>
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
 * @brief Create a self-signed root CA certificate for @p key with an explicit validity window.
 *
 * Attestation roots are long-lived; this overload lets a test pin a root that outlives any
 * leaf so that leaf-expiry tests are not masked by root expiry.
 * @return A DER @ref TestCert; check @c valid() for success.
 */
[[nodiscard]]
TestCert create_root(const TestKey &key, std::string_view common_name, std::chrono::seconds validity);

/**
 * @brief Create a leaf certificate for @p subject signed by @p issuer_key / @p issuer_cert.
 */
[[nodiscard]]
TestCert create_leaf(const TestKey &subject, const TestKey &issuer_key, const TestCert &issuer_cert,
                     std::string_view common_name);

/**
 * @brief Spec for a fabricated attestation leaf: one vendor extension (@c extension_oid, empty =
 * none) whose @c extension_value becomes the extnValue OCTET STRING content verbatim, plus a
 * validity window as offsets from now (negative = in the past, so expiry is testable).
 */
struct AttestationLeafSpec
{
    std::string_view common_name;
    std::string_view extension_oid;
    std::span<const std::byte> extension_value;
    bool extension_critical{false};
    std::chrono::seconds not_before_from_now{std::chrono::seconds{0}};
    std::chrono::seconds not_after_from_now{std::chrono::seconds{31536000}};
};

/**
 * @brief Create a leaf certificate from @p spec, signed by @p issuer_key / @p issuer_cert.
 *
 * Used to fabricate hardware-independent attestation chains (e.g. an Apple ACME leaf carrying
 * the SHA-256 nonce in OID 1.2.840.113635.100.8.11.1).
 * @return A DER @ref TestCert; check @c valid() for success.
 */
[[nodiscard]]
TestCert create_attestation_leaf(const TestKey &subject, const TestKey &issuer_key, const TestCert &issuer_cert,
                                 const AttestationLeafSpec &spec);

} // namespace mpss::tests::mock_pki
