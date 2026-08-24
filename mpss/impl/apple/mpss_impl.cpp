// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/impl/apple/apple_api_wrapper.h"
#include "mpss/impl/apple/apple_keychain_keypair.h"
#include "mpss/impl/apple/apple_se_keypair.h"
#include "mpss/impl/apple/apple_se_wrapper.h"
#include "mpss/impl/apple/apple_utils.h"
#include "mpss/impl/key_probe.h"
#include "mpss/utils/utilities.h"
#include <optional>

namespace mpss::impl::os
{

using enum Algorithm;

namespace
{

using OpenKeyResult = KeyProbeResult<std::unique_ptr<KeyPair>>;

std::optional<bool> measure_keychain_isolation(const std::string &key_name)
{
    using enum utils::AppleOperationResult;

    bool hardware_backed = false;
    const std::int32_t raw_result = MPSS_GetKeyIsolation(key_name.c_str(), &hardware_backed);
    switch (utils::decode_apple_result(raw_result))
    {
    case success:
        return hardware_backed;
    case operational_error:
        utils::report_keychain_error("classify key storage");
        return std::nullopt;
    case expected_negative:
        mpss::utils::log_and_set_error("Keychain could not classify key '{}' after opening it.", key_name);
        return std::nullopt;
    case invalid_result:
        utils::report_invalid_apple_result("Keychain", "classify key storage", raw_result);
        return std::nullopt;
    }

    return std::nullopt;
}

std::unique_ptr<KeyPair> validate_created_key(std::unique_ptr<KeyPair> key, std::string_view name,
                                             IsolationLevel minimum_isolation)
{
    if (mpss::meets_minimum_isolation(key->key_info().isolation_level, minimum_isolation))
    {
        return key;
    }

    const IsolationLevel actual_isolation = key->key_info().isolation_level;
    if (!key->delete_key())
    {
        const std::string cleanup_error = mpss::get_error();
        mpss::utils::log_and_set_error(
            "Newly created Apple key '{}' is below the requested minimum isolation and cleanup failed: {}", name,
            cleanup_error);
        return nullptr;
    }

    mpss::utils::log_and_set_error(
        "Newly created Apple key '{}' measured at isolation level {} below requested minimum {}.", name,
        static_cast<unsigned>(actual_isolation), static_cast<unsigned>(minimum_isolation));
    return nullptr;
}

OpenKeyResult try_open_key(const std::string &key_name, IsolationLevel minimum_isolation)
{
    using enum utils::AppleOperationResult;

    mpss::utils::log_trace("Attempting to open key '{}' on Apple backend.", key_name);
    if (mpss::meets_minimum_isolation(IsolationLevel::hardware, minimum_isolation) &&
        MPSS_SE_SecureEnclaveIsSupported())
    {
        const std::int32_t raw_result = MPSS_SE_OpenExistingKey(key_name.c_str());
        switch (utils::decode_apple_result(raw_result))
        {
        case success:
            mpss::utils::log_trace("Key '{}' found in Secure Enclave.", key_name);
            return {.status = KeyProbeStatus::found,
                    .value = std::make_unique<AppleSEKeyPair>(key_name, ecdsa_secp256r1_sha256)};
        case expected_negative:
            break;
        case operational_error:
            utils::report_secure_enclave_error("open key");
            return {.status = KeyProbeStatus::operational_error, .value = nullptr};
        case invalid_result:
            utils::report_invalid_apple_result("Secure Enclave", "open key", raw_result);
            return {.status = KeyProbeStatus::operational_error, .value = nullptr};
        }
    }

    if (IsolationLevel::software != minimum_isolation)
    {
        return {.status = KeyProbeStatus::not_found, .value = nullptr};
    }

    int bit_size = 0;
    const std::int32_t raw_result = MPSS_OpenExistingKey(key_name.c_str(), &bit_size);
    switch (utils::decode_apple_result(raw_result))
    {
    case success:
        break;
    case expected_negative:
        return {.status = KeyProbeStatus::not_found, .value = nullptr};
    case operational_error:
        utils::report_keychain_error("open key");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    case invalid_result:
        utils::report_invalid_apple_result("Keychain", "open key", raw_result);
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    Algorithm algorithm = unsupported;
    switch (bit_size)
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
        MPSS_RemoveKey(key_name.c_str());
        mpss::utils::log_and_set_error("Opened key '{}' has unsupported bit size {}.", key_name, bit_size);
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    const std::optional<bool> hardware_backed = measure_keychain_isolation(key_name);
    if (!hardware_backed.has_value())
    {
        MPSS_RemoveKey(key_name.c_str());
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    mpss::utils::log_trace("Key '{}' found in Keychain with algorithm '{}'.", key_name,
                           get_algorithm_info(algorithm).type_str);
    return {.status = KeyProbeStatus::found,
            .value = std::make_unique<AppleKeychainKeyPair>(key_name, algorithm, *hardware_backed)};
}

} // namespace

std::unique_ptr<KeyPair> open_key(std::string_view name, IsolationLevel minimum_isolation)
{
    mpss::utils::clear_error();
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    OpenKeyResult result = try_open_key(key_name, minimum_isolation);
    if (KeyProbeStatus::not_found == result.status)
    {
        mpss::utils::log_debug("Key '{}' not found.", key_name);
    }
    if (nullptr != result.value &&
        !mpss::meets_minimum_isolation(result.value->key_info().isolation_level, minimum_isolation))
    {
        result.value.reset();
        mpss::utils::log_and_set_error("Apple key '{}' does not meet the requested minimum isolation.", key_name);
        return nullptr;
    }

    return std::move(result.value);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                    IsolationLevel minimum_isolation)
{
    mpss::utils::clear_error();
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    constexpr auto supported_policy = static_cast<std::uint64_t>(KeyPolicy::apple_secure_enclave_user_presence);
    const auto raw_policy = static_cast<std::uint64_t>(policy);
    if (0 != (raw_policy & ~supported_policy))
    {
        mpss::utils::log_and_set_error("Apple backend does not support the requested key policy.");
        return nullptr;
    }

    const bool require_user_presence = KeyPolicy::none != (policy & KeyPolicy::apple_secure_enclave_user_presence);
    const bool secure_enclave_supported = MPSS_SE_SecureEnclaveIsSupported();
    if (require_user_presence && (!secure_enclave_supported || ecdsa_secp256r1_sha256 != algorithm))
    {
        mpss::utils::log_and_set_error(
            "Apple Secure Enclave user presence requires ecdsa_secp256r1_sha256 and an available Secure Enclave.");
        return nullptr;
    }

    OpenKeyResult existing_key = try_open_key(key_name, minimum_isolation);
    if (KeyProbeStatus::operational_error == existing_key.status)
    {
        return nullptr;
    }
    if (KeyProbeStatus::found == existing_key.status)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    if (secure_enclave_supported && ecdsa_secp256r1_sha256 == algorithm &&
        mpss::meets_minimum_isolation(IsolationLevel::hardware, minimum_isolation))
    {
        // Secure Enclave only supports ECDSA P256.
        mpss::utils::log_trace("Creating key '{}' in Secure Enclave.", key_name);
        if (MPSS_SE_CreateKey(key_name.c_str(), require_user_presence))
        {
            const std::int32_t raw_result = MPSS_SE_OpenExistingKey(key_name.c_str());
            if (utils::AppleOperationResult::success == utils::decode_apple_result(raw_result))
            {
                mpss::utils::log_trace("Key '{}' created in Secure Enclave.", key_name);
                return validate_created_key(std::make_unique<AppleSEKeyPair>(name, algorithm), name,
                                            minimum_isolation);
            }

            switch (utils::decode_apple_result(raw_result))
            {
            case utils::AppleOperationResult::operational_error:
                utils::report_secure_enclave_error("classify newly created key");
                break;
            case utils::AppleOperationResult::expected_negative:
                mpss::utils::log_and_set_error(
                    "Secure Enclave could not reopen newly created key '{}' to classify its storage.", key_name);
                break;
            case utils::AppleOperationResult::invalid_result:
                utils::report_invalid_apple_result("Secure Enclave", "classify newly created key", raw_result);
                break;
            case utils::AppleOperationResult::success:
                break;
            }

            const std::string classification_error = mpss::get_error();
            if (!MPSS_SE_RemoveExistingKey(key_name.c_str()))
            {
                const std::string cleanup_error = utils::take_secure_enclave_error();
                mpss::utils::log_and_set_error(
                    "Failed to classify newly created Secure Enclave key '{}': {}; cleanup failed: {}", key_name,
                    classification_error, cleanup_error);
            }
            return nullptr;
        }

        utils::report_secure_enclave_error("create key");
        return nullptr;
    }

    if (IsolationLevel::software != minimum_isolation)
    {
        mpss::utils::log_and_set_error(
            "Algorithm '{}' cannot satisfy the requested Apple minimum isolation.",
            get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    mpss::utils::log_trace("Creating key '{}' in Keychain.", key_name);
    if (MPSS_CreateKey(key_name.c_str(), static_cast<int>(algorithm)))
    {
        const std::optional<bool> hardware_backed = measure_keychain_isolation(key_name);
        if (!hardware_backed.has_value())
        {
            const std::string classification_error = mpss::get_error();
            if (!MPSS_DeleteKey(key_name.c_str()))
            {
                const std::string cleanup_error = utils::take_keychain_error();
                mpss::utils::log_and_set_error(
                    "Failed to classify newly created Keychain key '{}': {}; cleanup failed: {}", key_name,
                    classification_error, cleanup_error);
            }
            return nullptr;
        }

        mpss::utils::log_trace("Key '{}' created in Keychain.", key_name);
        return validate_created_key(std::make_unique<AppleKeychainKeyPair>(name, algorithm, *hardware_backed), name,
                                    minimum_isolation);
    }

    utils::report_keychain_error("create key");
    return nullptr;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    mpss::utils::clear_error();
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_and_set_error("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
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
        const std::int32_t raw_result = MPSS_SE_VerifyStandaloneSignature(
            reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
            reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
            reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());
        const bool result = utils::handle_secure_enclave_verification_result(raw_result, "verify signature");
        mpss::utils::log_trace("Verification using (Secure Enclave) standalone signature verification {}.",
                               result ? "succeeded" : "failed");
        return result;
    }

    const std::int32_t raw_result = MPSS_VerifyStandaloneSignature(
        static_cast<int>(algorithm), reinterpret_cast<const std::uint8_t *>(hash.data()), hash.size(),
        reinterpret_cast<const std::uint8_t *>(public_key.data()), public_key.size(),
        reinterpret_cast<const std::uint8_t *>(sig.data()), sig.size());
    const bool result = utils::handle_keychain_verification_result(raw_result, "verify signature");
    mpss::utils::log_trace("Verification using (Keychain) standalone signature verification {}.",
                           result ? "succeeded" : "failed");
    return result;
}

} // namespace mpss::impl::os
