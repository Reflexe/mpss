// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/attestation.h"
#include "mpss/mpss.h"
#include <optional>
#include <utility>

namespace mpss::impl::os
{

class AndroidKeyPair : public mpss::KeyPair
{
  public:
    AndroidKeyPair(mpss::Algorithm algorithm, std::string_view name, bool hardware_backed,
                   const char *storage_description, bool supports_attestation = false,
                   std::optional<mpss::AttestationEvidence> evidence = std::nullopt)
        : mpss::KeyPair{algorithm, hardware_backed, storage_description}, key_name_{name},
          supports_attestation_{supports_attestation}, attestation_evidence_{std::move(evidence)}
    {
    }

    ~AndroidKeyPair() override
    {
        // Release on destruction.
        close_key();
    }

    bool delete_key() override;

    [[nodiscard]]
    std::size_t sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;

    [[nodiscard]]
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;

    [[nodiscard]]
    std::size_t extract_key(std::span<std::byte> public_key) const override;

    [[nodiscard]]
    bool supports_attestation() const override
    {
        return supports_attestation_;
    }

    [[nodiscard]]
    std::optional<mpss::AttestationEvidence> attestation() const override
    {
        return attestation_evidence_;
    }

    void release_key() noexcept override;

  private:
    void close_key();
    [[nodiscard]]
    JNIEnv *env() const
    {
        return guard_.Env();
    };

    std::string key_name_;
    bool supports_attestation_{false};
    std::optional<mpss::AttestationEvidence> attestation_evidence_;
    JNIEnvGuard guard_;
};

} // namespace mpss::impl::os
