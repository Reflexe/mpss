// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tests/mock_pki/mock_pki.h"
#include <algorithm>
#include <functional>
#include <random>
#include <sstream>

namespace mpss::tests::mock_pki
{

namespace
{

constexpr std::string_view android_prefix = "MPSS_ANDROID_KEY_ATTESTATION_V1";
constexpr std::string_view windows_prefix = "MPSS_WINDOWS_TPM_ATTESTATION_V1";
constexpr std::string_view apple_prefix = "MPSS_APP_ATTEST_V1";
constexpr std::string_view apple_acme_prefix = "MPSS_APPLE_ACME_MDA_V1";

} // namespace

MockPkiService::MockPkiService(std::chrono::seconds ttl) : ttl_{ttl}
{
}

std::vector<std::byte> MockPkiService::issue_challenge()
{
    std::vector<std::byte> nonce(32);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::generate(nonce.begin(), nonce.end(), [&] { return static_cast<std::byte>(dist(gen)); });

    outstanding_[nonce_key(nonce)] = NonceState{std::chrono::steady_clock::now() + ttl_, false};
    return nonce;
}

SubmitResult MockPkiService::submit(const MockCsr &csr, const std::optional<AttestationEvidence> &evidence,
                                    AttestationFormat expected_format)
{
    if (!evidence.has_value())
    {
        return {false, RejectReason::missing_evidence, false};
    }
    return submit(csr, *evidence, expected_format);
}

SubmitResult MockPkiService::submit(const MockCsr &csr, const AttestationEvidence &evidence,
                                    AttestationFormat expected_format)
{
    if (AttestationFormat::none == evidence.format || expected_format != evidence.format)
    {
        return {false, RejectReason::wrong_format, false};
    }

    std::vector<std::byte> challenge;
    std::vector<std::byte> attested_public_key;
    if (AttestationFormat::android_key_attestation == evidence.format)
    {
        if (evidence.cert_chain.empty())
        {
            return {false, RejectReason::invalid_structure, false};
        }
        const std::span<const char> prefix_chars{android_prefix.data(), android_prefix.size()};
        if (!parse_challenge_and_key(evidence.statement, std::as_bytes(prefix_chars), challenge,
                                     attested_public_key))
        {
            return {false, RejectReason::invalid_structure, false};
        }
    }
    else if (AttestationFormat::windows_tpm == evidence.format)
    {
        const std::span<const char> prefix_chars{windows_prefix.data(), windows_prefix.size()};
        if (!parse_challenge_and_key(evidence.statement, std::as_bytes(prefix_chars), challenge,
                                     attested_public_key))
        {
            return {false, RejectReason::invalid_structure, false};
        }
    }
    else if (AttestationFormat::apple_app_attest == evidence.format)
    {
        if (evidence.statement.size() <= apple_prefix.size())
        {
            return {false, RejectReason::invalid_structure, false};
        }
        if (!std::equal(apple_prefix.begin(), apple_prefix.end(),
                        reinterpret_cast<const char *>(evidence.statement.data())))
        {
            return {false, RejectReason::invalid_structure, false};
        }
        challenge.assign(evidence.statement.begin() + static_cast<std::ptrdiff_t>(apple_prefix.size()),
                         evidence.statement.end() - static_cast<std::ptrdiff_t>(sizeof(std::size_t)));
        if (evidence.statement.size() < apple_prefix.size() + sizeof(std::size_t))
        {
            return {false, RejectReason::invalid_structure, false};
        }

        const std::string csr_key(reinterpret_cast<const char *>(csr.public_key.data()), csr.public_key.size());
        const std::size_t expected_binding = std::hash<std::string>{}(csr_key);
        std::size_t encoded_binding = 0;
        const std::size_t offset = evidence.statement.size() - sizeof(std::size_t);
        for (std::size_t i = 0; i < sizeof(std::size_t); ++i)
        {
            encoded_binding |=
                (static_cast<std::size_t>(std::to_integer<unsigned int>(evidence.statement[offset + i])) & 0xFFU)
                << (i * 8U);
        }
        if (encoded_binding != expected_binding)
        {
            return {false, RejectReason::public_key_mismatch, false};
        }
        attested_public_key = csr.public_key;
    }
    else if (AttestationFormat::apple_acme_managed_device_attestation == evidence.format)
    {
        if (evidence.cert_chain.empty())
        {
            return {false, RejectReason::invalid_structure, false};
        }
        const std::span<const char> prefix_chars{apple_acme_prefix.data(), apple_acme_prefix.size()};
        if (!parse_challenge_and_key(evidence.statement, std::as_bytes(prefix_chars), challenge, attested_public_key))
        {
            return {false, RejectReason::invalid_structure, false};
        }
    }

    const auto nonce_it = outstanding_.find(nonce_key(challenge));
    if (outstanding_.end() == nonce_it)
    {
        return {false, RejectReason::nonce_not_found, false};
    }
    if (nonce_it->second.used)
    {
        return {false, RejectReason::nonce_replayed, false};
    }
    if (std::chrono::steady_clock::now() > nonce_it->second.expires_at)
    {
        return {false, RejectReason::nonce_expired, false};
    }
    if (attested_public_key != csr.public_key)
    {
        return {false, RejectReason::public_key_mismatch, false};
    }

    nonce_it->second.used = true;
    const bool weaker_assurance = AttestationFormat::apple_app_attest == evidence.format;
    return {true, std::nullopt, weaker_assurance};
}

std::string MockPkiService::nonce_key(std::span<const std::byte> nonce)
{
    std::ostringstream out;
    for (const std::byte b : nonce)
    {
        out << std::hex << std::to_integer<unsigned int>(b);
    }
    return out.str();
}

bool MockPkiService::parse_challenge_and_key(std::span<const std::byte> statement, std::span<const std::byte> prefix,
                                             std::vector<std::byte> &challenge, std::vector<std::byte> &public_key)
{
    if (statement.size() < prefix.size() + 2)
    {
        return false;
    }
    if (!std::equal(prefix.begin(), prefix.end(), statement.begin()))
    {
        return false;
    }

    std::size_t offset = prefix.size();
    const std::size_t challenge_size = std::to_integer<std::size_t>(statement[offset]);
    ++offset;
    if (statement.size() < offset + challenge_size + 1)
    {
        return false;
    }
    challenge.assign(statement.begin() + static_cast<std::ptrdiff_t>(offset),
                     statement.begin() + static_cast<std::ptrdiff_t>(offset + challenge_size));
    offset += challenge_size;

    const std::size_t pk_size = std::to_integer<std::size_t>(statement[offset]);
    ++offset;
    if (statement.size() < offset + pk_size)
    {
        return false;
    }
    public_key.assign(statement.begin() + static_cast<std::ptrdiff_t>(offset),
                      statement.begin() + static_cast<std::ptrdiff_t>(offset + pk_size));
    return true;
}

} // namespace mpss::tests::mock_pki
