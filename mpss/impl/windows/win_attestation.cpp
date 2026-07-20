// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/windows/win_attestation.h"
#include "mpss/impl/windows/crypto_params.h"
#include "mpss/impl/windows/win_keypair.h"
#include "mpss/impl/windows/win_utils.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <Windows.h>
#include <cstddef>
#include <ncrypt.h>
#include <span>
#include <string>
#include <vector>

namespace mpss::impl::os
{

namespace
{

// Cosmetic KeyInfo label only; the evidence format is the authoritative signal.
constexpr const char *tpm_storage_description = "TPM Attestation";

// One attestation attempt: provider + creation flags + claim type/format to emit.
struct ClaimProfile
{
    LPCWSTR provider_name;
    DWORD create_flags;
    DWORD claim_type;
    AttestationFormat format;
    const char *storage_description;
};

NCRYPT_PROV_HANDLE open_provider(LPCWSTR provider_name)
{
    NCRYPT_PROV_HANDLE provider_handle = 0;
    const SECURITY_STATUS status = ::NCryptOpenStorageProvider(&provider_handle, provider_name, /* dwFlags */ 0);
    if (ERROR_SUCCESS != status || 0 == provider_handle)
    {
        mpss::utils::log_debug("NCryptOpenStorageProvider failed with error code {}.", mpss::utils::to_hex(status));
        return 0;
    }
    return provider_handle;
}

// Create + finalize a persisted EC key. The returned handle outlives the provider handle.
NCRYPT_KEY_HANDLE create_ec_key(NCRYPT_PROV_HANDLE provider, std::string_view name, Algorithm algorithm,
                                DWORD create_flags)
{
    crypto_params const *const crypto = utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return 0;
    }

    const std::wstring wname(name.begin(), name.end());
    NCRYPT_KEY_HANDLE key_handle = 0;
    SECURITY_STATUS status = ::NCryptCreatePersistedKey(provider, &key_handle, crypto->key_type_name(), wname.c_str(),
                                                        /* dwLegacyKeySpec */ 0, create_flags);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_debug("NCryptCreatePersistedKey failed with error code {}.", mpss::utils::to_hex(status));
        return 0;
    }

    status = ::NCryptFinalizeKey(key_handle, /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_debug("NCryptFinalizeKey failed with error code {}.", mpss::utils::to_hex(status));
        ::NCryptDeleteKey(key_handle, /* dwFlags */ 0);
        return 0;
    }

    return key_handle;
}

// Nonce-bound claim over the key; hAuthorityKey=NULL means the TPM AIK self-signs.
std::vector<std::byte> generate_claim(NCRYPT_KEY_HANDLE key, std::span<const std::byte> nonce, DWORD claim_type)
{
    const ULONG nonce_size = mpss::utils::narrow_or_error<ULONG>(nonce.size());
    if (0 == nonce_size)
    {
        return {};
    }

    BCryptBuffer nonce_buffer{};
    nonce_buffer.cbBuffer = nonce_size;
    nonce_buffer.BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE;
    nonce_buffer.pvBuffer = const_cast<std::byte *>(nonce.data());

    BCryptBufferDesc parameter_list{};
    parameter_list.ulVersion = BCRYPTBUFFER_VERSION;
    parameter_list.cBuffers = 1;
    parameter_list.pBuffers = &nonce_buffer;

    DWORD claim_size = 0;
    SECURITY_STATUS status = ::NCryptCreateClaim(key, /* hAuthorityKey */ 0, claim_type, &parameter_list,
                                                 /* pbClaimBlob */ nullptr, /* cbClaimBlob */ 0, &claim_size,
                                                 /* dwFlags */ 0);
    if (ERROR_SUCCESS != status || 0 == claim_size)
    {
        mpss::utils::log_debug("NCryptCreateClaim (size) failed with error code {}.", mpss::utils::to_hex(status));
        return {};
    }

    std::vector<std::byte> claim(claim_size);
    status = ::NCryptCreateClaim(key, /* hAuthorityKey */ 0, claim_type, &parameter_list,
                                 reinterpret_cast<PBYTE>(claim.data()), claim_size, &claim_size, /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_debug("NCryptCreateClaim (fill) failed with error code {}.", mpss::utils::to_hex(status));
        return {};
    }

    claim.resize(claim_size);
    return claim;
}

// One provider+claim attempt; deletes the key it created on failure so the caller can try the next.
std::unique_ptr<KeyPair> try_profile(const ClaimProfile &profile, std::string_view name, Algorithm algorithm,
                                     std::span<const std::byte> nonce)
{
    NCRYPT_PROV_HANDLE provider = open_provider(profile.provider_name);
    if (0 == provider)
    {
        return nullptr;
    }
    SCOPE_GUARD(::NCryptFreeObject(provider));

    NCRYPT_KEY_HANDLE key = create_ec_key(provider, name, algorithm, profile.create_flags);
    if (0 == key)
    {
        return nullptr;
    }

    std::vector<std::byte> claim = generate_claim(key, nonce, profile.claim_type);
    if (claim.empty())
    {
        // No claim means no attestation: delete the key rather than orphan an evidence-less one.
        ::NCryptDeleteKey(key, /* dwFlags */ 0);
        return nullptr;
    }

    AttestationEvidence evidence;
    evidence.format = profile.format;
    evidence.payload = std::move(claim);

    return std::make_unique<WindowsKeyPair>(algorithm, key, /* hardware_backed */ true, profile.storage_description,
                                            std::move(evidence));
}

} // namespace

std::unique_ptr<KeyPair> create_attested_key(std::string_view name, Algorithm algorithm,
                                             const AttestationRequest &request)
{
    if (request.challenge.empty())
    {
        mpss::utils::log_and_set_error("Attestation challenge cannot be empty.");
        return nullptr;
    }

    const std::span<const std::byte> nonce{request.challenge};

    // Only a TPM claim is externally verifiable (AIK -> EK -> published manufacturer root), so only it
    // counts as attestation evidence. VBS / Key Guard is key protection, applied on the normal create
    // path via NCRYPT_REQUIRE_VBS_FLAG -- not attestation; a VBS-only key carries no evidence.
    const ClaimProfile tpm_profile{MS_PLATFORM_KEY_STORAGE_PROVIDER, /* create_flags */ 0,
                                   NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT, AttestationFormat::windows_tpm_claim,
                                   tpm_storage_description};

    std::unique_ptr<KeyPair> key = try_profile(tpm_profile, name, algorithm, nonce);
    if (nullptr != key)
    {
        mpss::utils::log_trace("Created attested key '{}' with {}.", name, tpm_storage_description);
        return key;
    }

    mpss::utils::log_debug("No TPM attestation could produce evidence for key '{}'.", name);
    return nullptr;
}

} // namespace mpss::impl::os
