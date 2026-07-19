// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include "tests/mock_pki/test_ca.h"
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace mpss::tests::mock_pki
{

using mpss::attest::TrustAnchor;

/**
 * @brief A certificate-signing request carrying the public key to be certified.
 */
struct MockCsr
{
    std::vector<std::byte> public_key; // canonical DER SubjectPublicKeyInfo
};

/**
 * @brief Why the mock PKI refused to sign a CSR.
 */
enum class RejectReason
{
    missing_evidence,
    wrong_format,
    nonce_not_found,
    nonce_expired,
    nonce_replayed,
    verifier_rejected // the shared verifier declined
};

/**
 * @brief The outcome of submitting a CSR + attestation evidence.
 */
struct SubmitResult
{
    bool signed_cert{false};
    std::optional<RejectReason> reject_reason;

    // Populated once the verifier is consulted (after nonce checks pass), so tests can
    // assert submit() delegates verification.
    mpss::attest::AttestationVerifier::Result verifier_result;
};

/**
 * @brief A reduced mock PKI: nonce issue/expire/replay bookkeeping plus a call into the shared
 * @ref mpss::attest::AttestationVerifier.
 *
 * The nonce is supplied by the caller and never parsed from the evidence; all evidence
 * verification is delegated to the shared verifier (no home-grown blob parsing).
 */
class MockPkiService
{
  public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    explicit MockPkiService(std::chrono::seconds ttl = std::chrono::seconds{60});

    std::vector<std::byte> issue_challenge();

    void set_trusted_root(AttestationFormat format, TrustAnchor anchor);

    /**
     * @brief Override the clock used for nonce expiry, for deterministic tests.
     */
    void set_clock(Clock clock);

    /**
     * @brief Submit a CSR with evidence bound to @p nonce, expected to be @p expected_format.
     *
     * A nonce passing the freshness checks is spent (single-use), so replay is caught even
     * while the verifier only reports "not implemented".
     */
    SubmitResult submit(const MockCsr &csr, const std::optional<AttestationEvidence> &evidence,
                        std::span<const std::byte> nonce, AttestationFormat expected_format);

  private:
    struct NonceState
    {
        std::chrono::steady_clock::time_point expires_at;
        bool used{false};
    };

    static std::string nonce_key(std::span<const std::byte> nonce);

    [[nodiscard]]
    std::chrono::steady_clock::time_point now() const;

    [[nodiscard]]
    mpss::attest::AttestationVerifier make_verifier() const;

    std::chrono::seconds ttl_;
    Clock clock_;
    std::unordered_map<std::string, NonceState> outstanding_;
    std::unordered_map<AttestationFormat, TrustAnchor> trusted_roots_;
};

} // namespace mpss::tests::mock_pki
