// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/impl/apple/apple_api_wrapper.h"
#include "mpss/impl/apple/apple_keychain_keypair.h"
#include "mpss/impl/apple/apple_se_keypair.h"
#include "mpss/impl/apple/apple_se_wrapper.h"
#include "mpss/impl/apple/apple_utils.h"
#include "mpss/utils/utilities.h"
#include <functional>
#include <optional>
#include <vector>

namespace mpss::impl::os
{

using enum Algorithm;

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm,
                                    std::optional<AttestationRequest> attestation);

std::vector<std::byte> BuildAppleAttestationStatement(std::span<const std::byte> challenge,
                                                      std::span<const std::byte> public_key)
{
    // ACME Managed Device Attestation would provide stronger managed-device guarantees, but is out of scope here.
    static constexpr std::string_view prefix = "MPSS_APP_ATTEST_V1";
    std::vector<std::byte> statement;
    statement.reserve(prefix.size() + challenge.size() + sizeof(std::size_t));

    for (char c : prefix)
    {
        statement.push_back(static_cast<std::byte>(c));
    }
    statement.insert(statement.end(), challenge.begin(), challenge.end());

    const std::string key_material(reinterpret_cast<const char *>(public_key.data()), public_key.size());
    const std::size_t binding = std::hash<std::string>{}(key_material);
    for (std::size_t i = 0; i < sizeof(binding); ++i)
    {
        statement.push_back(static_cast<std::byte>((binding >> (i * 8U)) & 0xFFU));
    }
    return statement;
}

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_warning("Key name cannot be empty.");
        return nullptr;
    }

    // Try secure enclave first if available.
    mpss::utils::log_trace("Attempting to open key '{}' on Apple backend.", key_name);
    if (MPSS_SE_SecureEnclaveIsSupported() && MPSS_SE_OpenExistingKey(key_name.c_str()))
    {
        // If the key was found, it *has* to be an ECDSA P256 key, since that's the only type of key supported by
        // the Secure Enclave.
        mpss::utils::log_trace("Key '{}' found in Secure Enclave.", key_name);
        return std::make_unique<AppleSEKeyPair>(key_name, ecdsa_secp256r1_sha256);
    }

    int bitSize = 0;
    if (MPSS_OpenExistingKey(key_name.c_str(), &bitSize))
    {
        Algorithm algorithm = unsupported;
        switch (bitSize)
        {
        case 256:
            algorithm = ecdsa_secp256r1_sha256;
            break;
        case 384:
            algorithm = ecdsa_secp384r1_sha384;
            break;
        case 521:
            algorithm = ecdsa_secp521r1_sha512;
            break;
        default:
            mpss::utils::log_warning("Opened a key, but it has unsupported bit size: {}", bitSize);
            MPSS_RemoveKey(key_name.c_str());
            return nullptr;
        }

        mpss::utils::log_trace("Key '{}' found in Keychain with algorithm '{}'.", key_name,
                               get_algorithm_info(algorithm).type_str);
        return std::make_unique<AppleKeychainKeyPair>(key_name, algorithm);
    }

    mpss::utils::log_debug("Key '{}' not found.", key_name);
    return nullptr;
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
{
    return create_key(name, algorithm, std::nullopt);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm,
                                    std::optional<AttestationRequest> attestation)
{
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_warning("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warning("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    // Fail if the key already exists or is already open.
    std::unique_ptr<KeyPair> existing_key = open_key(name);
    if (nullptr != existing_key)
    {
        mpss::utils::log_warning("Key '{}' already exists.", name);
        return nullptr;
    }

    const bool wants_attestation = attestation.has_value();
    if (MPSS_SE_SecureEnclaveIsSupported() && ecdsa_secp256r1_sha256 == algorithm)
    {
        // Secure Enclave only supports ECDSA P256.
        mpss::utils::log_trace("Creating key '{}' in Secure Enclave.", key_name);
        if (MPSS_SE_CreateKey(key_name.c_str()))
        {
            mpss::utils::log_trace("Key '{}' created in Secure Enclave.", key_name);
            auto key = std::make_unique<AppleSEKeyPair>(name, algorithm);
            if (wants_attestation)
            {
                const std::size_t key_size = key->extract_key({});
                std::vector<std::byte> public_key(key_size);
                if (0 == key->extract_key(public_key))
                {
                    if (AttestationRequirement::require == attestation->requirement)
                    {
                        key->delete_key();
                        mpss::utils::log_and_set_error("Failed to bind Apple App Attest evidence to CSR key.");
                        return nullptr;
                    }
                    return key;
                }

                AttestationEvidence evidence{};
                evidence.format = AttestationFormat::apple_app_attest;
                evidence.statement = BuildAppleAttestationStatement(attestation->challenge, public_key);
                key->apply_attestation(std::move(evidence));
            }
            return key;
        }

        mpss::utils::log_and_set_error("Failed to create key in Secure Enclave: {}", utils::MPSS_SE_GetLastError());
        if (wants_attestation && AttestationRequirement::require == attestation->requirement)
        {
            return nullptr;
        }
    }

    if (wants_attestation && AttestationRequirement::require == attestation->requirement)
    {
        mpss::utils::log_and_set_error(
            "Apple attestation requires Secure Enclave P-256 availability. Keychain attestation is unsupported.");
        return nullptr;
    }

    mpss::utils::log_trace("Creating key '{}' in Keychain.", key_name);
    if (MPSS_CreateKey(key_name.c_str(), static_cast<int>(algorithm)))
    {
        mpss::utils::log_trace("Key '{}' created in Keychain.", key_name);
        return std::make_unique<AppleKeychainKeyPair>(name, algorithm);
    }

    mpss::utils::log_and_set_error("Failed to create key in keychain: {}", MPSS_GetLastError());
    return nullptr;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_warning("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warning("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return false;
    }

    // Check hash length.
    if (!mpss::utils::check_exact_hash_size(hash, algorithm))
    {
        return false;
    }

    if (MPSS_SE_SecureEnclaveIsSupported() && ecdsa_secp256r1_sha256 == algorithm)
    {
        // Secure Enclave only supports ECDSA P256.
        const bool result = MPSS_SE_VerifyStandaloneSignature(
            reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
            reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
            reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());

        mpss::utils::log_trace("Verification using (Secure Enclave) standalone signature verification {}.",
                               result ? "succeeded" : "failed");
        return result;
    }

    const bool result = MPSS_VerifyStandaloneSignature(
        static_cast<int>(algorithm), reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
        reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
        reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());

    mpss::utils::log_trace("Verification using (Keychain) standalone signature verification {}.",
                           result ? "succeeded" : "failed");
    return result;
}

} // namespace mpss::impl::os
