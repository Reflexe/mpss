// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "tests/mock_pki/test_ca.h"
#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace mpss::tests::mock_pki
{

constexpr long android_one_year_seconds = 31536000L;

/**
 * @brief A KeyMint attestation security level, as encoded in the KeyDescription extension.
 */
enum class TestSecurityLevel
{
    software = 0,
    trusted_environment = 1,
    strongbox = 2,
};

/**
 * @brief Builds a DER-encoded Android KeyDescription (ext 1.3.6.1.4.1.11129.2.1.17 content).
 *
 * Only the challenge and security level carry meaningful values; the surrounding fields
 * (versions, uniqueId, two empty authorization lists) exist only to mirror a real structure.
 */
[[nodiscard]]
std::vector<std::byte> make_key_description(std::span<const std::byte> challenge, TestSecurityLevel level);

/**
 * @brief Options controlling a fabricated Android attestation certificate.
 */
struct AndroidCertOptions
{
    std::string_view common_name;
    long serial{1};
    bool is_ca{false};

    // Offsets in seconds relative to "now", not absolute times.
    long not_before_offset_seconds{0};
    long not_after_offset_seconds{android_one_year_seconds};

    // When set, embed this KeyDescription as the attestation extension.
    std::optional<std::vector<std::byte>> key_description{};
};

/**
 * @brief Fabricates an X.509 certificate for @p subject signed by @p issuer_key / @p issuer_cert.
 *
 * A null @p issuer_cert produces a self-signed root. Check @c valid() on the result.
 */
[[nodiscard]]
TestCert make_android_cert(const TestKey &subject, const TestKey &issuer_key, const TestCert *issuer_cert,
                           const AndroidCertOptions &opts);

/**
 * @brief Extracts a certificate's serial-number bytes the same way the verifier does, so a test can
 * build a revocation set the verifier's check will match.
 */
[[nodiscard]]
std::vector<std::byte> cert_serial_bytes(const TestCert &cert);

} // namespace mpss::tests::mock_pki
