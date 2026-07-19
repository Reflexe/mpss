// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/windows/win_keypair.h"
#include "mpss/impl/windows/win_utils.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <codecvt>
#include <cwchar>
#include <locale>
#include <ncrypt.h>
#include <string>

namespace
{

using enum mpss::Algorithm;

// Legacy key spec. We only store signing keys.
constexpr DWORD key_spec = 0;

// Primary provider: prefer the TPM-backed Platform Crypto Provider as the strongest available root of trust.
constexpr LPCWSTR provider_name = MS_PLATFORM_KEY_STORAGE_PROVIDER;

// Fallback when the TPM is unavailable: VBS, requested via the require_vbs flag.
constexpr LPCWSTR fallback_provider_name = MS_KEY_STORAGE_PROVIDER;

// A description of our default provider
constexpr LPCSTR provider_description = "TPM Protection";

// A description of our fallback provider
constexpr LPCSTR fallback_provider_description = "Virtualization Based Security";

// A description of the software fallback, used when no hardware-backed provider is available.
constexpr LPCSTR software_description = "Software Protection";

// Older SDK headers do not define NCRYPT_REQUIRE_VBS_FLAG; fall back to its documented value.
#ifdef NCRYPT_REQUIRE_VBS_FLAG
constexpr DWORD require_vbs = NCRYPT_REQUIRE_VBS_FLAG;
#else
constexpr DWORD require_vbs = 0x00020000;
#endif

// Per-key property reporting whether a key in MS_KEY_STORAGE_PROVIDER is VBS-isolated. Older SDK
// headers do not define it.
#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY
#define NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY L"Virtual Iso"
#endif

// To open the key for the local machine, set this to NCRYPT_MACHINE_KEY_FLAG.
// Setting this to 0 opens the key for the current user.
constexpr DWORD key_open_mode = 0;

NCRYPT_PROV_HANDLE GetProvider(LPCWSTR provider_name_to_use)
{
    NCRYPT_PROV_HANDLE provider_handle = 0;

    // This function uses no extra flags.
    DWORD flags = 0;

    SECURITY_STATUS status = ::NCryptOpenStorageProvider(&provider_handle, provider_name_to_use, flags);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptOpenStorageProvider failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return 0;
    }

    if (0 == provider_handle)
    {
        mpss::utils::log_and_set_error("Provider handle is null.");
        return 0;
    }

    return provider_handle;
}

NCRYPT_KEY_HANDLE GetKeyFromProvider(std::string_view name, bool fallback)
{
    NCRYPT_PROV_HANDLE provider_handle = GetProvider(fallback ? fallback_provider_name : provider_name);
    if (0 == provider_handle)
    {
        return 0;
    }

    SCOPE_GUARD(::NCryptFreeObject(provider_handle));
    NCRYPT_KEY_HANDLE key_handle = 0;
    const std::wstring wname(name.begin(), name.end());

    SECURITY_STATUS status = ::NCryptOpenKey(provider_handle, &key_handle, wname.c_str(), key_spec, key_open_mode);
    if (ERROR_SUCCESS != status)
    {
        if (static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET) != status)
        {
            mpss::utils::log_and_set_error("NCryptOpenKey failed with error code {}.", mpss::utils::to_hex(status));
        }
        return 0;
    }

    // This tier opened the key; clear any error a previously-tried tier left set (a not-found tier
    // deliberately leaves its error) so a successful open reports no error.
    mpss::utils::set_error({});
    return key_handle;
}

bool IsVirtualIsolationKey(NCRYPT_KEY_HANDLE key_handle)
{
    DWORD virtual_isolation = 0;
    DWORD output_size = 0;
    SECURITY_STATUS status = ::NCryptGetProperty(key_handle, NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY,
                                                 reinterpret_cast<PBYTE>(&virtual_isolation), sizeof(virtual_isolation),
                                                 &output_size, /* dwFlags */ 0);
    return ERROR_SUCCESS == status && 0 != virtual_isolation;
}

NCRYPT_KEY_HANDLE GetKey(std::string_view name, const char **storage_description, bool *hardware_backed)
{
    *storage_description = nullptr;
    *hardware_backed = false;

    // Try the TPM provider first.
    NCRYPT_KEY_HANDLE key_handle = GetKeyFromProvider(name, /* fallback */ false);
    if (0 != key_handle)
    {
        *storage_description = provider_description;
        *hardware_backed = true;
        return key_handle;
    }

    // The software KSP holds both VBS-isolated and plain software keys; tell them apart per key.
    key_handle = GetKeyFromProvider(name, /* fallback */ true);
    if (0 != key_handle)
    {
        if (IsVirtualIsolationKey(key_handle))
        {
            *storage_description = fallback_provider_description;
            *hardware_backed = true;
        }
        else
        {
            *storage_description = software_description;
            *hardware_backed = false;
        }
        return key_handle;
    }

    return 0;
}

NCRYPT_KEY_HANDLE CreateKey(std::string_view name, mpss::Algorithm algorithm, bool fallback, DWORD create_flags)
{
    mpss::impl::os::crypto_params const *const crypto = mpss::impl::os::utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", mpss::get_algorithm_info(algorithm).type_str);
        return 0;
    }

    NCRYPT_PROV_HANDLE provider_handle = GetProvider(fallback ? fallback_provider_name : provider_name);
    if (0 == provider_handle)
    {
        return 0;
    }
    SCOPE_GUARD(::NCryptFreeObject(provider_handle));

    NCRYPT_KEY_HANDLE key_handle = 0;
    const std::wstring wname(name.begin(), name.end());

    SECURITY_STATUS status = ::NCryptCreatePersistedKey(provider_handle, &key_handle, crypto->key_type_name(),
                                                        wname.c_str(), key_spec, key_open_mode | create_flags);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptCreatePersistedKey failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return 0;
    }

    // Delete the half-created key if we fail before handing it to the caller. NCryptDeleteKey frees
    // the handle on success; free it explicitly if the delete itself fails.
    SCOPE_GUARD({
        if (0 != key_handle)
        {
            if (ERROR_SUCCESS != ::NCryptDeleteKey(key_handle, /* dwFlags */ 0))
            {
                ::NCryptFreeObject(key_handle);
            }
        }
    });

    // Make the private key non-exportable. Must be set before the key is finalized.
    DWORD export_policy = 0;
    status = ::NCryptSetProperty(key_handle, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy),
                                 sizeof(export_policy), /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptSetProperty (export policy) failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return 0;
    }

    status = ::NCryptFinalizeKey(key_handle, /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptFinalizeKey failed with error code {}.", mpss::utils::to_hex(status));
        return 0;
    }

    // This tier created the key; clear any error a previously-tried tier left set so a successful
    // create reports no error.
    mpss::utils::set_error({});

    const NCRYPT_KEY_HANDLE result = key_handle;
    key_handle = 0; // Disarm the cleanup guard: ownership passes to the caller.
    return result;
}

mpss::Algorithm GetAlgorithmFromName(NCRYPT_KEY_HANDLE key_handle)
{
    DWORD dwOutputSize = 0;

    SECURITY_STATUS status = ::NCryptGetProperty(key_handle, NCRYPT_ALGORITHM_PROPERTY,
                                                 /* pbOutput */ nullptr,
                                                 /* cbOutput */ 0, &dwOutputSize,
                                                 /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptGetProperty (algorithm) failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return unsupported;
    }

    std::wstring algorithm_name(dwOutputSize, '\0');
    const DWORD algorithm_name_size = mpss::utils::narrow_or_error<DWORD>(algorithm_name.size());
    if (0 == algorithm_name_size)
    {
        return unsupported;
    }

    status = ::NCryptGetProperty(key_handle, NCRYPT_ALGORITHM_PROPERTY, reinterpret_cast<PBYTE>(&algorithm_name[0]),
                                 algorithm_name_size, &dwOutputSize,
                                 /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptGetProperty failed with error code {}.", mpss::utils::to_hex(status));
        return unsupported;
    }

    if (algorithm_name.starts_with(NCRYPT_ECDSA_P256_ALGORITHM))
    {
        return ecdsa_secp256r1_sha256;
    }
    if (algorithm_name.starts_with(NCRYPT_ECDSA_P384_ALGORITHM))
    {
        return ecdsa_secp384r1_sha384;
    }
    if (algorithm_name.starts_with(NCRYPT_ECDSA_P521_ALGORITHM))
    {
        return ecdsa_secp521r1_sha512;
    }

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    const std::string alg_name = converter.to_bytes(algorithm_name);
    return unsupported;
}

std::size_t GetKeyLength(NCRYPT_KEY_HANDLE key_handle)
{
    DWORD dwKeyLength = 0;
    DWORD dwOutputSize = 0;

    SECURITY_STATUS status = ::NCryptGetProperty(key_handle, NCRYPT_LENGTH_PROPERTY,
                                                 reinterpret_cast<PBYTE>(&dwKeyLength), sizeof(DWORD), &dwOutputSize,
                                                 /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptGetProperty (length) failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return 0;
    }

    return static_cast<std::size_t>(dwKeyLength);
}

mpss::Algorithm GuessAlgorithmFromKeyBits(std::size_t key_bits)
{
    switch (key_bits)
    {
    case 256:
        return ecdsa_secp256r1_sha256;
    case 384:
        return ecdsa_secp384r1_sha384;
    case 521:
        return ecdsa_secp521r1_sha512;
    default:
        return unsupported;
    }
}
} // namespace

namespace mpss::impl::os
{
using enum Algorithm;

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_warning("Key name cannot be empty.");
        return {};
    }

    mpss::utils::log_trace("Attempting to open key '{}' on Windows backend.", name);

    Algorithm algorithm{unsupported};

    const char *storage_description = nullptr;
    bool hardware_backed = false;
    NCRYPT_KEY_HANDLE key_handle = GetKey(name, &storage_description, &hardware_backed);
    if (0 == key_handle)
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
        return nullptr;
    }

    SCOPE_GUARD({
        // Release if algorithm is not set, which means there was an error opening the key.
        if (unsupported == algorithm)
        {
            ::NCryptFreeObject(key_handle);
        }
    });

    // Get the algorithm name to deduce SignatureAlgorithm.
    algorithm = GetAlgorithmFromName(key_handle);
    if (unsupported == algorithm)
    {
        // Try directly with the key size.
        algorithm = GuessAlgorithmFromKeyBits(GetKeyLength(key_handle));
        if (unsupported == algorithm)
        {
            return nullptr;
        }
    }

    mpss::utils::log_trace("Key '{}' opened with {} storage.", name, storage_description);
    return std::make_unique<WindowsKeyPair>(algorithm, key_handle, hardware_backed, storage_description);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
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

    // Try the TPM provider first.
    mpss::utils::log_trace("Creating key '{}' with {} provider.", name, provider_description);
    NCRYPT_KEY_HANDLE key_handle = CreateKey(name, algorithm, /* fallback */ false, /* create_flags */ 0);
    if (0 != key_handle)
    {
        mpss::utils::log_trace("Key '{}' created with {} provider.", name, provider_description);
        return std::make_unique<WindowsKeyPair>(algorithm, key_handle, /* hardware_backed */ true,
                                                provider_description);
    }
    std::string errors = std::string{provider_description} + ": " + mpss::utils::get_error();

    // Fall back to a VBS-isolated key in the software KSP.
    mpss::utils::log_trace("Creating key '{}' with {} provider.", name, fallback_provider_description);
    key_handle = CreateKey(name, algorithm, /* fallback */ true, /* create_flags */ require_vbs);
    if (0 != key_handle)
    {
        mpss::utils::log_trace("Key '{}' created with {} provider.", name, fallback_provider_description);
        return std::make_unique<WindowsKeyPair>(algorithm, key_handle, /* hardware_backed */ true,
                                                fallback_provider_description);
    }
    errors += "; " + std::string{fallback_provider_description} + ": " + mpss::utils::get_error();

    // Last resort: a plain software key. Still non-exportable, but not hardware-backed.
    mpss::utils::log_trace("Creating key '{}' with {} provider.", name, software_description);
    key_handle = CreateKey(name, algorithm, /* fallback */ true, /* create_flags */ 0);
    if (0 != key_handle)
    {
        mpss::utils::log_trace("Key '{}' created with {} provider.", name, software_description);
        return std::make_unique<WindowsKeyPair>(algorithm, key_handle, /* hardware_backed */ false,
                                                software_description);
    }
    errors += "; " + std::string{software_description} + ": " + mpss::utils::get_error();

    mpss::utils::log_and_set_error("Failed to create key '{}': {}", name, errors);

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

    // Check compression indicator
    if (public_key[0] != std::byte{0x04})
    {
        mpss::utils::log_warning("Invalid public key format.");
        return false;
    }

    // Get the algorithm info.
    const AlgorithmInfo info = get_algorithm_info(algorithm);

    // Get crypto parameters.
    crypto_params const *const crypto = utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        mpss::utils::log_warning("Unsupported algorithm '{}'.", info.type_str);
        return false;
    }

    // Build the key blob.
    const DWORD pk_blob_size = sizeof(crypto_params::key_blob_t) + public_key.size() - 1;
    std::unique_ptr<BYTE[]> key_blob_buffer = std::make_unique<BYTE[]>(pk_blob_size);

    crypto_params::key_blob_t *key_blob = reinterpret_cast<crypto_params::key_blob_t *>(key_blob_buffer.get());
    key_blob->dwMagic = crypto->public_key_magic();
    key_blob->cbKey = mpss::utils::narrow_or_error<ULONG>((info.key_bits + 7) / 8);
    if (0 == key_blob->cbKey)
    {
        return false;
    }

    // Copy public key data to the blob.
    std::transform(public_key.begin() + 1, public_key.end(), key_blob_buffer.get() + sizeof(crypto_params::key_blob_t),
                   [](auto in) { return static_cast<BYTE>(in); });

    // verify() imports an external public key, which only the software KSP supports. Open it
    // explicitly so verification does not depend on the create/open ladder ordering.
    NCRYPT_PROV_HANDLE provider = GetProvider(MS_KEY_STORAGE_PROVIDER);
    if (0 == provider)
    {
        return false;
    }
    SCOPE_GUARD(::NCryptFreeObject(provider));

    // Import the public key.
    NCRYPT_KEY_HANDLE key_handle = 0;
    SECURITY_STATUS status =
        ::NCryptImportKey(provider,
                          /* hImportKey */ 0, crypto->public_key_blob_name(),
                          /* pParameterList */ nullptr, &key_handle, key_blob_buffer.get(), pk_blob_size,
                          /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptImportKey failed with error code {}.", mpss::utils::to_hex(status));
        return false;
    }
    if (0 == key_handle)
    {
        mpss::utils::log_and_set_error("Failed to import key.");
        return false;
    }
    SCOPE_GUARD(::NCryptFreeObject(key_handle));

    // Extract the raw signature.
    std::size_t raw_sig_size = utils::decode_raw_signature(sig, algorithm, {});
    if (0 == raw_sig_size)
    {
        return false;
    }

    std::unique_ptr<std::byte[]> raw_sig = std::make_unique<std::byte[]>(raw_sig_size);
    std::span<std::byte> raw_sig_span(raw_sig.get(), raw_sig_size);
    raw_sig_size = utils::decode_raw_signature(sig, algorithm, raw_sig_span);

    const DWORD hash_size = mpss::utils::narrow_or_error<DWORD>(hash.size());
    if (0 == hash_size)
    {
        return false;
    }

    status = ::NCryptVerifySignature(key_handle,
                                     /* pPaddingInfo */ nullptr,
                                     reinterpret_cast<PBYTE>(const_cast<std::byte *>(hash.data())), hash_size,
                                     reinterpret_cast<PBYTE>(raw_sig.get()), raw_sig_size,
                                     /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        // This should not fail at this point unless the signature is invalid. The inputs are already validated.
        return false;
    }

    return true;
}

} // namespace mpss::impl::os
