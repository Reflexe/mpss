// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/attestation.h"
#include <chrono>
#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace mpss::attest
{

/**
 * @brief A pinned trust anchor for a given attestation format.
 *
 * In Stage 1 this simply carries the DER bytes of a root certificate (or raw public key).
 * Later stages parse and chain evidence to these anchors.
 */
struct TrustAnchor
{
    /** @brief DER-encoded root certificate (or SubjectPublicKeyInfo). */
    std::vector<std::byte> der;
};

/**
 * @brief Platform-agnostic verifier for hardware key-attestation evidence.
 *
 * A single interface fronts per-format verifiers, each of which validates evidence against
 * the correct pinned vendor roots, checks nonce freshness, and enforces revocation/expiry.
 * The result echoes the evidence @ref AttestationFormat so a relying party can distinguish
 * externally-verifiable formats from the VBS test-lane format.
 *
 * Stage 1 ships the skeleton only: every per-format verifier is a stub that reports
 * "not implemented". Real per-format logic lands in Stages 2-4.
 */
class AttestationVerifier
{
  public:
    /**
     * @brief Injectable policy for verification (roots, clock, revocation, minimum level).
     */
    struct Policy
    {
        /** @brief Returns the pinned trust anchors for a given format. */
        std::function<std::vector<TrustAnchor>(AttestationFormat)> roots;

        /** @brief Injectable clock, so captured vectors can be replayed offline. */
        std::function<std::chrono::system_clock::time_point()> clock;

        /** @brief Returns true if the certificate/claim serial is revoked. */
        std::function<bool(std::span<const std::byte> serial)> is_revoked;

        /** @brief The minimum acceptable hardware security level. */
        AttestationSecurityLevel min_security_level{AttestationSecurityLevel::unknown};
    };

    /**
     * @brief The outcome of a verification.
     */
    struct Result
    {
        /** @brief True only if the evidence verified fully against the policy. */
        bool ok{false};

        /** @brief The evidence format (lets the caller distinguish real vs VBS). */
        AttestationFormat format{AttestationFormat::none};

        /** @brief The security level parsed from the evidence. */
        AttestationSecurityLevel security_level{AttestationSecurityLevel::unknown};

        /** @brief Human-readable explanation, especially on failure. */
        std::string reason;
    };

    AttestationVerifier() = default;

    explicit AttestationVerifier(Policy policy);

    /**
     * @brief Verifies attestation evidence against the configured policy.
     * @param[in] evidence The evidence to verify.
     * @param[in] expected_nonce The nonce the relying party expects to be bound in the evidence.
     * @param[in] expected_pubkey The public key (canonical DER SubjectPublicKeyInfo) the evidence must attest.
     * @return A @ref Result whose @c ok is true only on full success.
     */
    [[nodiscard]]
    Result verify(const AttestationEvidence &evidence, std::span<const std::byte> expected_nonce,
                  std::span<const std::byte> expected_pubkey) const;

  private:
    Policy policy_;
};

} // namespace mpss::attest
