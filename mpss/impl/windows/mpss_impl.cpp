// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/windows/ncrypt_handle.h"
#include "mpss/impl/windows/win_keypair.h"
#include "mpss/impl/windows/win_utils.h"
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

// The TPM-backed Platform Crypto Provider is the only provider this backend creates or opens keys
// in. It is the strongest tier Windows offers, and the only one that can be classified from the
// provider identity alone.
constexpr LPCWSTR provider_name = MS_PLATFORM_KEY_STORAGE_PROVIDER;

// A description of our provider.
constexpr LPCSTR provider_description = "TPM Protection";

// The guarantee a key in the Platform KSP provides. Windows never reports secure_element: CNG
// exposes no reliable way to tell a discrete TPM from a firmware, integrated, or virtual one, so
// the claim stops at dedicated hardware.
constexpr mpss::SecurityType provider_security_type = mpss::SecurityType::hardware;

// To open the key for the local machine, set this to NCRYPT_MACHINE_KEY_FLAG.
// Setting this to 0 opens the key for the current user.
constexpr DWORD key_open_mode = 0;

using mpss::impl::os::NcryptHandle;
using mpss::impl::os::NcryptUncommittedKey;

NcryptHandle GetProvider(LPCWSTR provider_name_to_use)
{
    NcryptHandle provider;

    // This function uses no extra flags.
    DWORD flags = 0;

    SECURITY_STATUS status = ::NCryptOpenStorageProvider(provider.out_ptr(), provider_name_to_use, flags);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptOpenStorageProvider failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return {};
    }

    if (!provider)
    {
        mpss::utils::log_and_set_error("Provider handle is null.");
        return {};
    }

    return provider;
}

NcryptHandle GetKeyFromProvider(std::string_view name)
{
    const NcryptHandle provider = GetProvider(provider_name);
    if (!provider)
    {
        return {};
    }

    NcryptHandle key;
    const std::wstring wname(name.begin(), name.end());

    SECURITY_STATUS status =
        ::NCryptOpenKey(provider.get(), key.out_ptr(), wname.c_str(), key_spec, key_open_mode);
    if (ERROR_SUCCESS != status)
    {
        if (static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET) != status)
        {
            mpss::utils::log_and_set_error("NCryptOpenKey failed with error code {}.", mpss::utils::to_hex(status));
        }
        return {};
    }

    return key;
}

NcryptUncommittedKey CreateKey(std::string_view name, mpss::Algorithm algorithm)
{
    mpss::impl::os::crypto_params const *const crypto = mpss::impl::os::utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", mpss::get_algorithm_info(algorithm).type_str);
        return {};
    }

    const NcryptHandle provider = GetProvider(provider_name);
    if (!provider)
    {
        return {};
    }

    NCRYPT_KEY_HANDLE raw_key = 0;
    const std::wstring wname(name.begin(), name.end());

    SECURITY_STATUS status = ::NCryptCreatePersistedKey(provider.get(), &raw_key, crypto->key_type_name(),
                                                        wname.c_str(), key_spec, key_open_mode);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptCreatePersistedKey failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return {};
    }

    // A key is persisted from this point on, so take ownership of it immediately: any failure below
    // now removes it instead of leaving an unusable key behind.
    NcryptUncommittedKey key{raw_key};

    status = ::NCryptFinalizeKey(key.get(), /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptFinalizeKey failed with error code {}.", mpss::utils::to_hex(status));
        return {};
    }

    return key;
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

std::unique_ptr<KeyPair> open_key(std::string_view name, SecurityType min_security)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return {};
    }

    if (!meets_minimum(provider_security_type, min_security))
    {
        mpss::utils::log_and_set_error(
            "The Windows backend cannot guarantee security '{}'; the strongest it provides is '{}'.",
            to_string(min_security), to_string(provider_security_type));
        return nullptr;
    }

    mpss::utils::log_trace("Attempting to open key '{}' on Windows backend.", name);

    NcryptHandle key = GetKeyFromProvider(name);
    if (!key)
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
        return nullptr;
    }

    // Get the algorithm name to deduce SignatureAlgorithm.
    Algorithm algorithm = GetAlgorithmFromName(key.get());
    if (unsupported == algorithm)
    {
        // Try directly with the key size.
        algorithm = GuessAlgorithmFromKeyBits(GetKeyLength(key.get()));
        if (unsupported == algorithm)
        {
            // Returning here closes the handle; the stored key is left untouched.
            return nullptr;
        }
    }

    mpss::utils::log_trace("Key '{}' opened with {} storage.", name, provider_description);

    // Construct first, then commit: if the allocation throws, the handle is still owned here and
    // gets closed rather than leaked.
    auto key_pair =
        std::make_unique<WindowsKeyPair>(algorithm, key.get(), provider_security_type, provider_description);
    static_cast<void>(key.release());
    return key_pair;
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                    SecurityType min_security)
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

    // Prune before touching the provider: no mechanism this backend can request reaches a floor
    // above the Platform KSP's guarantee, so such a request fails before a key is persisted.
    if (!meets_minimum(provider_security_type, min_security))
    {
        mpss::utils::log_and_set_error(
            "The Windows backend cannot guarantee security '{}'; the strongest it provides is '{}'.",
            to_string(min_security), to_string(provider_security_type));
        return nullptr;
    }

    // Fail if the key already exists or is already open. The lookup uses no floor of its own: a
    // name collision is a collision regardless of what the caller asked this key to guarantee.
    std::unique_ptr<KeyPair> existing_key = open_key(name, SecurityType::software);
    if (nullptr != existing_key)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    mpss::utils::log_trace("Creating key '{}' with {} provider.", name, provider_description);
    NcryptUncommittedKey key = CreateKey(name, algorithm);
    if (!key)
    {
        mpss::utils::log_and_set_error("Failed to create key '{}' with {} provider: {}", name, provider_description,
                                       mpss::utils::get_error());
        return nullptr;
    }

    mpss::utils::log_trace("Key '{}' created with {} provider.", name, provider_description);

    // Construct first, then commit: if the allocation throws, the key is still uncommitted and gets
    // deleted rather than orphaned in the provider.
    auto key_pair =
        std::make_unique<WindowsKeyPair>(algorithm, key.get(), provider_security_type, provider_description);
    static_cast<void>(key.release());
    return key_pair;
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

    // verify() imports an external public key, which the Platform KSP does not accept. Open the
    // software KSP explicitly: this path handles caller-supplied public keys only and never touches
    // a stored private key, so it is independent of which provider holds MPSS keys.
    const NcryptHandle provider = GetProvider(MS_KEY_STORAGE_PROVIDER);
    if (!provider)
    {
        return false;
    }

    // Import the public key.
    NcryptHandle imported_key;
    SECURITY_STATUS status =
        ::NCryptImportKey(provider.get(),
                          /* hImportKey */ 0, crypto->public_key_blob_name(),
                          /* pParameterList */ nullptr, imported_key.out_ptr(), key_blob_buffer.get(), pk_blob_size,
                          /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptImportKey failed with error code {}.", mpss::utils::to_hex(status));
        return false;
    }
    if (!imported_key)
    {
        mpss::utils::log_and_set_error("Failed to import key.");
        return false;
    }

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

    status = ::NCryptVerifySignature(imported_key.get(),
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
