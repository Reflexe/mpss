// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/attestation.h"
#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace mpss::tests::mock_pki
{

struct MockCsr
{
    std::vector<std::byte> public_key;
};

enum class RejectReason
{
    missing_evidence,
    wrong_format,
    nonce_not_found,
    nonce_expired,
    nonce_replayed,
    nonce_mismatch,
    public_key_mismatch,
    invalid_structure
};

struct SubmitResult
{
    bool signed_cert{false};
    std::optional<RejectReason> reject_reason;
    bool weaker_assurance{false};
};

class MockPkiService
{
  public:
    explicit MockPkiService(std::chrono::seconds ttl = std::chrono::seconds{60});

    std::vector<std::byte> issue_challenge();

    SubmitResult submit(const MockCsr &csr, const AttestationEvidence &evidence, AttestationFormat expected_format);

    SubmitResult submit(const MockCsr &csr, const std::optional<AttestationEvidence> &evidence,
                        AttestationFormat expected_format);

  private:
    struct NonceState
    {
        std::chrono::steady_clock::time_point expires_at;
        bool used{false};
    };

    std::chrono::seconds ttl_;
    std::unordered_map<std::string, NonceState> outstanding_;

    static std::string nonce_key(std::span<const std::byte> nonce);
    static bool parse_challenge_and_key(std::span<const std::byte> statement, std::span<const std::byte> prefix,
                                        std::vector<std::byte> &challenge, std::vector<std::byte> &public_key);
};

} // namespace mpss::tests::mock_pki
