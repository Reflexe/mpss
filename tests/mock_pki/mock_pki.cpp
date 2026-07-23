// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tests/mock_pki/mock_pki.h"
#include <algorithm>
#include <random>
#include <utility>

namespace mpss::tests::mock_pki
{

MockPkiService::MockPkiService(std::chrono::seconds ttl)
    : ttl_{ttl}, clock_{[] { return std::chrono::steady_clock::now(); }}
{
}

void MockPkiService::set_trusted_root(AttestationFormat format, TrustAnchor anchor)
{
    trusted_roots_[format] = std::move(anchor);
}

void MockPkiService::set_clock(Clock clock)
{
    clock_ = std::move(clock);
}

std::chrono::steady_clock::time_point MockPkiService::now() const
{
    return clock_();
}

std::vector<std::byte> MockPkiService::issue_challenge()
{
    std::vector<std::byte> nonce(32);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::generate(nonce.begin(), nonce.end(), [&] { return static_cast<std::byte>(dist(gen)); });

    outstanding_[nonce_key(nonce)] = NonceState{now() + ttl_, false};
    return nonce;
}

std::string MockPkiService::nonce_key(std::span<const std::byte> nonce)
{
    // Fixed-width two hex digits per byte so distinct nonces never collide.
    static constexpr char hex_digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(nonce.size() * 2);
    for (const std::byte b : nonce)
    {
        const auto value = std::to_integer<unsigned int>(b);
        out.push_back(hex_digits[(value >> 4U) & 0x0FU]);
        out.push_back(hex_digits[value & 0x0FU]);
    }
    return out;
}

mpss::attest::AttestationVerifier MockPkiService::make_verifier() const
{
    mpss::attest::AttestationVerifier::Policy policy;
    policy.roots = [roots = trusted_roots_](AttestationFormat format) {
        std::vector<mpss::attest::TrustAnchor> anchors;
        const auto it = roots.find(format);
        if (roots.end() != it)
        {
            anchors.push_back(it->second);
        }
        return anchors;
    };
    policy.clock = [] { return std::chrono::system_clock::now(); };
    policy.is_revoked = [](std::span<const std::byte>) { return false; };
    return mpss::attest::AttestationVerifier{std::move(policy)};
}

SubmitResult MockPkiService::submit(const MockCsr &csr, const std::optional<AttestationEvidence> &evidence,
                                    std::span<const std::byte> nonce, AttestationFormat expected_format)
{
    if (!evidence.has_value())
    {
        return SubmitResult{false, RejectReason::missing_evidence, {}};
    }

    if (AttestationFormat::none == evidence->format || expected_format != evidence->format)
    {
        return SubmitResult{false, RejectReason::wrong_format, {}};
    }

    // Nonce supplied explicitly, never parsed from the evidence.
    const auto it = outstanding_.find(nonce_key(nonce));
    if (outstanding_.end() == it)
    {
        return SubmitResult{false, RejectReason::nonce_not_found, {}};
    }
    if (it->second.used)
    {
        return SubmitResult{false, RejectReason::nonce_replayed, {}};
    }
    if (now() > it->second.expires_at)
    {
        return SubmitResult{false, RejectReason::nonce_expired, {}};
    }

    // Spend the nonce on presentation so replay is caught even if verification fails.
    it->second.used = true;

    const mpss::attest::AttestationVerifier verifier = make_verifier();
    mpss::attest::AttestationVerifier::Result result = verifier.verify(*evidence, nonce, csr.public_key);
    if (!result.ok)
    {
        return SubmitResult{false, RejectReason::verifier_rejected, std::move(result)};
    }

    return SubmitResult{true, std::nullopt, std::move(result)};
}

} // namespace mpss::tests::mock_pki
