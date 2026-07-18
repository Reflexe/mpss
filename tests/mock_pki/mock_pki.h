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
    verifier_rejected // the shared verifier declined (in Stage 1: "not implemented")
};

/**
 * @brief The outcome of submitting a CSR + attestation evidence.
 */
struct SubmitResult
{
    bool signed_cert{false};
    std::optional<RejectReason> reject_reason;

    // Populated whenever the shared verifier was actually consulted (i.e. after the nonce
    // bookkeeping passed). Lets tests assert that submit() delegates verification.
    mpss::attest::AttestationVerifier::Result verifier_result;
};

/**
 * @brief A reduced mock PKI: nonce issue/expire/replay bookkeeping plus a call into the shared
 * @ref mpss::attest::AttestationVerifier.
 *
 * It performs NO home-grown blob parsing: the nonce is provided explicitly by the caller (as a
 * real relying party would track the challenge it issued), and all evidence verification is
 * delegated to the shared verifier. Nonces are keyed by an unambiguous zero-padded hex encoding.
 */
class MockPkiService
{
  public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    explicit MockPkiService(std::chrono::seconds ttl = std::chrono::seconds{60});

    /**
     * @brief Issue a fresh random nonce and remember it as outstanding.
     */
    std::vector<std::byte> issue_challenge();

    /**
     * @brief Pin a trust anchor for a format; forwarded to the verifier policy.
     */
    void set_trusted_root(AttestationFormat format, TrustAnchor anchor);

    /**
     * @brief Override the clock used for nonce expiry (for deterministic tests).
     */
    void set_clock(Clock clock);

    /**
     * @brief Submit a CSR with evidence bound to @p nonce, expected to be @p expected_format.
     *
     * The nonce is passed explicitly and never parsed out of the evidence. A nonce that passes
     * the freshness checks is spent (single-use) regardless of the verifier's decision, so replay
     * is detectable even while the Stage 1 verifier only reports "not implemented".
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
