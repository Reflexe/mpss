// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/attestation.h"
#include "mpss/mpss.h"
#include <Windows.h>
#include <ncrypt.h>
#include <optional>
#include <utility>

namespace mpss::impl::os
{

class WindowsKeyPair : public mpss::KeyPair
{
  public:
    WindowsKeyPair(mpss::Algorithm algorithm, NCRYPT_KEY_HANDLE handle, bool hardware_backed,
                   const char *storage_description)
        : mpss::KeyPair(algorithm, hardware_backed, storage_description), key_handle_(handle)
    {
    }

    ~WindowsKeyPair() override
    {
        win_release();
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

    void set_attestation(std::optional<mpss::AttestationEvidence> evidence)
    {
        attestation_evidence_ = std::move(evidence);
        supports_attestation_ = true;
    }

  private:
    NCRYPT_KEY_HANDLE key_handle_ = 0;
    bool supports_attestation_{false};
    std::optional<mpss::AttestationEvidence> attestation_evidence_;

    void win_release() noexcept;

    void clear_handle() noexcept;
};

} // namespace mpss::impl::os
