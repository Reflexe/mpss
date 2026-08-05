// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/windows/win_keypair.h"
#include "mpss/impl/windows/win_utils.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <Windows.h>
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

// The software KSP holds both VBS-isolated and plain software keys.
constexpr LPCWSTR tpm_provider_name = MS_PLATFORM_KEY_STORAGE_PROVIDER;
constexpr LPCWSTR software_ksp_name = MS_KEY_STORAGE_PROVIDER;

constexpr LPCSTR tpm_description = "TPM Protection";
constexpr LPCSTR vbs_description = "Virtualization Based Security";
constexpr LPCSTR software_description = "Software Protection";

// Older SDK headers lack this flag.
#ifdef NCRYPT_REQUIRE_VBS_FLAG
constexpr DWORD require_vbs = NCRYPT_REQUIRE_VBS_FLAG;
#else
constexpr DWORD require_vbs = 0x00020000;
#endif

// Older SDK headers lack this property; it marks a key as VBS-isolated.
#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY
#define NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY L"Virtual Iso"
#endif

struct key_storage_provider
{
    NCRYPT_KEY_HANDLE (*create_key)(std::string_view, mpss::Algorithm);
    const char *storage_description;
    bool is_hardware_backed;
};

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

NCRYPT_KEY_HANDLE OpenKeyInProvider(LPCWSTR provider_name_to_use, std::string_view name)
{
    NCRYPT_PROV_HANDLE provider_handle = GetProvider(provider_name_to_use);
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

    // An earlier provider that did not hold the key left an error; clear it.
    mpss::utils::set_error({});
    return key_handle;
}

NCRYPT_KEY_HANDLE OpenKeyTpm(std::string_view name)
{
    return OpenKeyInProvider(tpm_provider_name, name);
}

NCRYPT_KEY_HANDLE OpenKeySoftwareKsp(std::string_view name)
{
    return OpenKeyInProvider(software_ksp_name, name);
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

    NCRYPT_KEY_HANDLE key_handle = OpenKeyTpm(name);
    if (0 != key_handle)
    {
        *storage_description = tpm_description;
        *hardware_backed = true;
        return key_handle;
    }

    key_handle = OpenKeySoftwareKsp(name);
    if (0 != key_handle)
    {
        if (IsVirtualIsolationKey(key_handle))
        {
            *storage_description = vbs_description;
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

NCRYPT_KEY_HANDLE CreateKeyInProvider(LPCWSTR provider_name_to_use, std::string_view name, mpss::Algorithm algorithm,
                                      DWORD create_flags)
{
    mpss::impl::os::crypto_params const *const crypto = mpss::impl::os::utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", mpss::get_algorithm_info(algorithm).type_str);
        return 0;
    }

    NCRYPT_PROV_HANDLE provider_handle = GetProvider(provider_name_to_use);
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

    // NCryptDeleteKey frees the handle on success, so only free it explicitly if the delete fails.
    SCOPE_GUARD({
        if (0 != key_handle)
        {
            if (ERROR_SUCCESS != ::NCryptDeleteKey(key_handle, /* dwFlags */ 0))
            {
                ::NCryptFreeObject(key_handle);
            }
        }
    });

    // Must be set before the key is finalized.
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

    // An earlier provider left an error; clear it now that one has succeeded.
    mpss::utils::set_error({});

    const NCRYPT_KEY_HANDLE result = key_handle;
    key_handle = 0; // Disarm the cleanup guard: ownership passes to the caller.
    return result;
}

// VBS and software share a CNG provider and differ only by the require_vbs flag.
NCRYPT_KEY_HANDLE CreateKeyTpm(std::string_view name, mpss::Algorithm algorithm)
{
    return CreateKeyInProvider(tpm_provider_name, name, algorithm, /* create_flags */ 0);
}

NCRYPT_KEY_HANDLE CreateKeyVbs(std::string_view name, mpss::Algorithm algorithm)
{
    return CreateKeyInProvider(software_ksp_name, name, algorithm, require_vbs);
}

NCRYPT_KEY_HANDLE CreateKeySoftware(std::string_view name, mpss::Algorithm algorithm)
{
    return CreateKeyInProvider(software_ksp_name, name, algorithm, /* create_flags */ 0);
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
        mpss::utils::log_and_set_error("Key name cannot be empty.");
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

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy)
{
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

    if (KeyPolicy::none != policy)
    {
        mpss::utils::log_and_set_error("Windows backend does not support the requested key policy.");
        return nullptr;
    }

    // Fail if the key already exists or is already open.
    std::unique_ptr<KeyPair> existing_key = open_key(name);
    if (nullptr != existing_key)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    // Strongest protection first: the first provider that creates a key wins.
    static constexpr key_storage_provider create_providers[] = {
        {.create_key = CreateKeyTpm, .storage_description = tpm_description, .is_hardware_backed = true},
        {.create_key = CreateKeyVbs, .storage_description = vbs_description, .is_hardware_backed = true},
        {.create_key = CreateKeySoftware, .storage_description = software_description, .is_hardware_backed = false},
    };

    // Report why each provider failed; the reasons usually differ.
    std::string errors;
    for (const key_storage_provider &provider : create_providers)
    {
        mpss::utils::log_trace("Creating key '{}' with {} provider.", name, provider.storage_description);
        const NCRYPT_KEY_HANDLE key_handle = provider.create_key(name, algorithm);
        if (0 != key_handle)
        {
            mpss::utils::log_trace("Key '{}' created with {} provider.", name, provider.storage_description);
            return std::make_unique<WindowsKeyPair>(algorithm, key_handle, provider.is_hardware_backed,
                                                    provider.storage_description);
        }

        if (!errors.empty())
        {
            errors += "; ";
        }
        errors += std::string{provider.storage_description} + ": " + mpss::utils::get_error();
    }

    mpss::utils::log_and_set_error("Failed to create key '{}': {}", name, errors);

    return nullptr;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
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

    // Check compression indicator
    if (public_key[0] != std::byte{0x04})
    {
        mpss::utils::log_and_set_error("Invalid public key format.");
        return false;
    }

    // Get the algorithm info.
    const AlgorithmInfo info = get_algorithm_info(algorithm);

    // Get crypto parameters.
    crypto_params const *const crypto = utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", info.type_str);
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

    // Verification only needs the public key, so the software KSP is enough.
    NCRYPT_PROV_HANDLE provider = GetProvider(software_ksp_name);
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
