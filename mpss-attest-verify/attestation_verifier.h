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
 */
struct TrustAnchor
{
    /** @brief DER-encoded root certificate (or SubjectPublicKeyInfo). */
    std::vector<std::byte> der;
};

/**
 * @brief Platform-agnostic verifier for hardware key-attestation evidence.
 *
 * A single interface fronts per-format verifiers; the result echoes the evidence
 * @ref AttestationFormat so a relying party can refuse the VBS test-lane format.
 * Stages 2-4 supply the per-format logic; the current verifiers are stubs.
 */
class AttestationVerifier
{
  public:
    /**
     * @brief Injectable verification inputs.
     */
    struct Policy
    {
        std::function<std::vector<TrustAnchor>(AttestationFormat)> roots;

        /** @brief Injectable clock so captured vectors can be replayed offline. */
        std::function<std::chrono::system_clock::time_point()> clock;

        std::function<bool(std::span<const std::byte> serial)> is_revoked;
    };

    /**
     * @brief The outcome of a verification.
     */
    struct Result
    {
        bool ok{false};

        /** @brief Echoed so the caller can distinguish real formats from VBS. */
        AttestationFormat format{AttestationFormat::none};

        std::string reason;
    };

    AttestationVerifier() = default;

    explicit AttestationVerifier(Policy policy);

    /**
     * @brief Verifies attestation evidence against the configured policy.
     * @param[in] expected_pubkey Canonical DER SubjectPublicKeyInfo the evidence must attest.
     */
    [[nodiscard]]
    Result verify(const AttestationEvidence &evidence, std::span<const std::byte> expected_nonce,
                  std::span<const std::byte> expected_pubkey) const;

  private:
    Policy policy_;
};

} // namespace mpss::attest
