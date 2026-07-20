// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/os_backend.h"
#include "mpss/impl/backend_registry.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl
{

namespace os
{

// Forward declarations for platform-specific implementations.
// These are implemented in each platform's mpss_impl.cpp.
[[nodiscard]]
std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm);
#if defined(_WIN32)
// Windows attests keys (TPM / VBS); other platforms have no attested overload yet.
[[nodiscard]]
std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm,
                                    const std::optional<AttestationRequest> &attestation);
#endif
[[nodiscard]]
std::unique_ptr<KeyPair> open_key(std::string_view name);
[[nodiscard]]
bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig);
[[nodiscard]]
AttestationCapability attestation_capability();

} // namespace os

std::unique_ptr<KeyPair> OSBackend::create_key(std::string_view name, Algorithm algorithm,
                                               std::optional<AttestationRequest> attestation,
                                               KeyPolicy /*policy*/) const
{
#if defined(_WIN32)
    return os::create_key(name, algorithm, attestation);
#else
    // Other OS backends have no attested path yet; ignore the request and create a plain key.
    if (attestation.has_value())
    {
        utils::log_debug("OS backend does not produce attestation evidence yet; creating key '{}' without it.", name);
    }
    return os::create_key(name, algorithm);
#endif
}

AttestationCapability OSBackend::attestation_capability() const
{
    return os::attestation_capability();
}

std::unique_ptr<KeyPair> OSBackend::open_key(std::string_view name) const
{
    return os::open_key(name);
}

bool OSBackend::verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                       std::span<const std::byte> sig) const
{
    return os::verify(hash, public_key, algorithm, sig);
}

void register_os_backend()
{
    auto backend = std::make_shared<OSBackend>();
    register_backend(backend);
}

} // namespace mpss::impl
