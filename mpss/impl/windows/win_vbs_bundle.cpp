// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/windows/win_vbs_bundle.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <Windows.h>
#include <array>
#include <bcrypt.h>
#include <ncrypt.h>
#include <string>
#include <tbs.h>
#include <vector>

namespace mpss::impl::os
{

namespace
{

// TPM2_Quote over every PCR (24-bit selection), matching the Azure VBS protocol's "all PCRs".
constexpr LONG all_pcrs_mask = 0x00FFFFFF;

std::string base64url(std::span<const std::byte> data)
{
    static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 3 <= data.size(); i += 3)
    {
        const std::uint32_t n = (std::to_integer<std::uint32_t>(data[i]) << 16) |
                                (std::to_integer<std::uint32_t>(data[i + 1]) << 8) |
                                std::to_integer<std::uint32_t>(data[i + 2]);
        out.push_back(table[(n >> 18) & 0x3F]);
        out.push_back(table[(n >> 12) & 0x3F]);
        out.push_back(table[(n >> 6) & 0x3F]);
        out.push_back(table[n & 0x3F]);
    }
    if (data.size() - i == 1)
    {
        const std::uint32_t n = std::to_integer<std::uint32_t>(data[i]) << 16;
        out.push_back(table[(n >> 18) & 0x3F]);
        out.push_back(table[(n >> 12) & 0x3F]);
    }
    else if (data.size() - i == 2)
    {
        const std::uint32_t n =
            (std::to_integer<std::uint32_t>(data[i]) << 16) | (std::to_integer<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(table[(n >> 18) & 0x3F]);
        out.push_back(table[(n >> 12) & 0x3F]);
        out.push_back(table[(n >> 6) & 0x3F]);
    }
    return out;
}

std::string base64url(const std::vector<BYTE> &data)
{
    return base64url(std::as_bytes(std::span<const BYTE>{data}));
}

// A unique persisted-key name so concurrent callers don't collide; the AIK is ephemeral and deleted
// once the quote is produced.
std::wstring unique_aik_name()
{
    std::array<BYTE, 16> random{};
    ::BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::wstring name = L"mpss_aik_";
    for (const BYTE b : random)
    {
        static constexpr wchar_t hex[] = L"0123456789abcdef";
        name.push_back(hex[b >> 4]);
        name.push_back(hex[b & 0x0F]);
    }
    return name;
}

std::vector<BYTE> export_property(NCRYPT_HANDLE handle, LPCWSTR property)
{
    DWORD size = 0;
    if (ERROR_SUCCESS != ::NCryptGetProperty(handle, property, nullptr, 0, &size, 0) || 0 == size)
    {
        return {};
    }
    std::vector<BYTE> value(size);
    if (ERROR_SUCCESS != ::NCryptGetProperty(handle, property, value.data(), size, &size, 0))
    {
        return {};
    }
    value.resize(size);
    return value;
}

std::vector<BYTE> export_aik_public(NCRYPT_KEY_HANDLE aik)
{
    DWORD size = 0;
    if (ERROR_SUCCESS != ::NCryptExportKey(aik, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0, &size, 0) || 0 == size)
    {
        return {};
    }
    std::vector<BYTE> blob(size);
    if (ERROR_SUCCESS != ::NCryptExportKey(aik, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, blob.data(), size, &size, 0))
    {
        return {};
    }
    blob.resize(size);
    return blob;
}

// BCRYPT_RSAKEY_BLOB header: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2 (6 ULONGs),
// then the public exponent and modulus big-endian. Emit the JWK members n and e.
bool rsa_blob_to_jwk(const std::vector<BYTE> &blob, std::string &jwk_n, std::string &jwk_e)
{
    constexpr std::size_t header = 6 * sizeof(ULONG);
    if (blob.size() < header)
    {
        return false;
    }
    const auto exponent_size = *reinterpret_cast<const ULONG *>(blob.data() + 2 * sizeof(ULONG));
    const auto modulus_size = *reinterpret_cast<const ULONG *>(blob.data() + 3 * sizeof(ULONG));
    if (header + static_cast<std::uint64_t>(exponent_size) + modulus_size > blob.size())
    {
        return false;
    }
    const std::span<const std::byte> bytes = std::as_bytes(std::span<const BYTE>{blob});
    jwk_e = base64url(bytes.subspan(header, exponent_size));
    jwk_n = base64url(bytes.subspan(header + exponent_size, modulus_size));
    return true;
}

// AIK-signed TPM quote over all PCRs (NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT). The AIK is the
// authority (hSubjectKey is NULL for a platform claim); the nonce binds freshness into the quote.
std::vector<BYTE> platform_quote(NCRYPT_KEY_HANDLE aik, std::span<const std::byte> nonce)
{
    LONG mask = all_pcrs_mask;
    std::array<BCryptBuffer, 2> buffers{};
    buffers[0].BufferType = NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK;
    buffers[0].cbBuffer = sizeof(mask);
    buffers[0].pvBuffer = &mask;
    buffers[1].BufferType = NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE;
    buffers[1].cbBuffer = mpss::utils::narrow_or_error<ULONG>(nonce.size());
    buffers[1].pvBuffer = const_cast<std::byte *>(nonce.data());

    BCryptBufferDesc parameters{};
    parameters.ulVersion = BCRYPTBUFFER_VERSION;
    parameters.cBuffers = static_cast<ULONG>(buffers.size());
    parameters.pBuffers = buffers.data();

    DWORD size = 0;
    SECURITY_STATUS status =
        ::NCryptCreateClaim(/* hSubjectKey */ 0, aik, NCRYPT_CLAIM_PLATFORM, &parameters, nullptr, 0, &size, 0);
    if (ERROR_SUCCESS != status || 0 == size)
    {
        mpss::utils::log_debug("Platform quote (size) failed with error code {}.", mpss::utils::to_hex(status));
        return {};
    }
    std::vector<BYTE> quote(size);
    status = ::NCryptCreateClaim(/* hSubjectKey */ 0, aik, NCRYPT_CLAIM_PLATFORM, &parameters, quote.data(), size,
                                 &size, 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_debug("Platform quote (fill) failed with error code {}.", mpss::utils::to_hex(status));
        return {};
    }
    quote.resize(size);
    return quote;
}

std::vector<BYTE> srtm_boot_log()
{
    UINT32 size = 0;
    if (TBS_SUCCESS != ::Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_BOOT, nullptr, &size) || 0 == size)
    {
        return {};
    }
    std::vector<BYTE> log(size);
    if (TBS_SUCCESS != ::Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_BOOT, log.data(), &size))
    {
        return {};
    }
    log.resize(size);
    return log;
}

} // namespace

std::optional<std::vector<std::byte>> build_vbs_offline_bundle(std::span<const std::byte> vbs_claim,
                                                               std::span<const std::byte> challenge)
{
    if (vbs_claim.empty() || challenge.empty())
    {
        return std::nullopt;
    }

    NCRYPT_PROV_HANDLE provider = 0;
    if (ERROR_SUCCESS != ::NCryptOpenStorageProvider(&provider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) || 0 == provider)
    {
        mpss::utils::log_debug("VBS bundle: platform crypto provider unavailable (no TPM anchor).");
        return std::nullopt;
    }
    SCOPE_GUARD(::NCryptFreeObject(provider));

    const std::wstring aik_name = unique_aik_name();
    NCRYPT_KEY_HANDLE aik = 0;
    if (ERROR_SUCCESS != ::NCryptCreatePersistedKey(provider, &aik, BCRYPT_RSA_ALGORITHM, aik_name.c_str(), 0, 0))
    {
        mpss::utils::log_debug("VBS bundle: AIK creation failed.");
        return std::nullopt;
    }
    SCOPE_GUARD(::NCryptDeleteKey(aik, 0));

    DWORD usage = NCRYPT_PCP_IDENTITY_KEY;
    ::NCryptSetProperty(aik, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage), 0);
    if (ERROR_SUCCESS != ::NCryptFinalizeKey(aik, 0))
    {
        mpss::utils::log_debug("VBS bundle: AIK finalize failed.");
        return std::nullopt;
    }

    const std::vector<BYTE> aik_blob = export_aik_public(aik);
    std::string jwk_n;
    std::string jwk_e;
    if (!rsa_blob_to_jwk(aik_blob, jwk_n, jwk_e))
    {
        mpss::utils::log_debug("VBS bundle: could not export AIK public key.");
        return std::nullopt;
    }

    const std::vector<BYTE> quote = platform_quote(aik, challenge);
    if (quote.empty())
    {
        return std::nullopt;
    }

    const std::vector<BYTE> log = srtm_boot_log();
    if (log.empty())
    {
        mpss::utils::log_debug("VBS bundle: SRTM measured-boot log unavailable.");
        return std::nullopt;
    }

    // Optional AIK certificate (present on TPMs enrolled with an attestation CA); absent on a bare
    // vTPM, where the relying party anchors the AIK public key by enrollment.
    const std::vector<BYTE> aik_cert = export_property(aik, NCRYPT_CERTIFICATE_PROPERTY);

    std::string json;
    json.reserve(log.size() * 2);
    json += R"({"att_type":"vbs","att_data":{"report_signed":{"tpm_att_data":{"srtm_boot_log":")";
    json += base64url(log);
    json += R"(","aik_pub":{"kty":"RSA","n":")";
    json += jwk_n;
    json += R"(","e":")";
    json += jwk_e;
    json += R"("},"current_claim":")";
    json += base64url(quote);
    json += '"';
    if (!aik_cert.empty())
    {
        json += R"(,"aik_cert":")";
        json += base64url(aik_cert);
        json += '"';
    }
    json += R"(}},"vsm_report":")";
    json += base64url(vbs_claim);
    json += R"("}})";

    const auto *const first = reinterpret_cast<const std::byte *>(json.data());
    return std::vector<std::byte>(first, first + json.size());
}

} // namespace mpss::impl::os
