// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// These tests use gmock-win32 to intercept the NCrypt free functions the Windows
// backend calls, so failure and fallback paths that can't be provoked on real
// hardware (every tier failing, a finalize failure, a rejected export policy) are
// exercised deterministically. IAT patching only reaches the executable it runs in,
// so this is its own executable linked against the static backend; it deliberately
// does not link the OpenSSL provider, whose algorithm-probing path conflicts with
// gmock-win32's process-global patching.

#if defined(_WIN32)

#include "mpss/key_info.h"
#include "mpss/mpss.h"
#include <gmock-win32.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <cwchar>
#include <span>
#include <string>
#include <vector>

#include <Windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

// Older SDK headers do not define this per-key property; mirror the backend's fallback so the
// mocked reads use the same property name the backend queries.
#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY
#define NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY L"Virtual Iso"
#endif

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptOpenStorageProvider, NCRYPT_PROV_HANDLE *, LPCWSTR, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptOpenKey, NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *, LPCWSTR, DWORD, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptCreatePersistedKey, NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *, LPCWSTR, LPCWSTR,
                  DWORD, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptSetProperty, NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptFinalizeKey, NCRYPT_KEY_HANDLE, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptGetProperty, NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD *, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptDeleteKey, NCRYPT_KEY_HANDLE, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptFreeObject, NCRYPT_HANDLE);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptSignHash, NCRYPT_KEY_HANDLE, VOID *, PBYTE, DWORD, PBYTE, DWORD, DWORD *, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptVerifySignature, NCRYPT_KEY_HANDLE, VOID *, PBYTE, DWORD, PBYTE, DWORD, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptExportKey, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc *,
                  PBYTE, DWORD, DWORD *, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptImportKey, NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc *,
                  NCRYPT_KEY_HANDLE *, PBYTE, DWORD, DWORD);

namespace
{

constexpr NCRYPT_PROV_HANDLE kFakeProvider = 0x1001;
constexpr NCRYPT_KEY_HANDLE kFakeKey = 0x2001;
constexpr SECURITY_STATUS kNotFound = static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET);
constexpr SECURITY_STATUS kFailure = static_cast<SECURITY_STATUS>(NTE_FAIL);

// P-256 sizes used by the fake NCrypt property/export/sign responses.
constexpr DWORD kP256KeyBytes = 32;
constexpr DWORD kP256RawSigBytes = 2 * kP256KeyBytes;
constexpr DWORD kP256PublicBlobBytes = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * kP256KeyBytes;

// Serves the property reads that open_key performs: the algorithm name, the VBS isolation flag,
// and the key length. A null algorithm name makes the algorithm read fail.
void InstallGetProperty(const wchar_t *alg_name, DWORD isolation, DWORD key_bits)
{
    EXPECT_MODULE_FUNC_CALL(NCryptGetProperty, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(
            Invoke([alg_name, isolation, key_bits](NCRYPT_HANDLE, LPCWSTR prop, PBYTE out, DWORD cb, DWORD *pcb,
                                                   DWORD) -> SECURITY_STATUS {
                if (0 == wcscmp(prop, NCRYPT_ALGORITHM_PROPERTY))
                {
                    if (nullptr == alg_name)
                    {
                        return kFailure;
                    }
                    const DWORD bytes = static_cast<DWORD>((wcslen(alg_name) + 1) * sizeof(wchar_t));
                    if (nullptr == out)
                    {
                        if (pcb)
                        {
                            *pcb = bytes;
                        }
                        return ERROR_SUCCESS;
                    }
                    if (cb < bytes)
                    {
                        return static_cast<SECURITY_STATUS>(NTE_BUFFER_TOO_SMALL);
                    }
                    std::memcpy(out, alg_name, bytes);
                    if (pcb)
                    {
                        *pcb = bytes;
                    }
                    return ERROR_SUCCESS;
                }
                if (0 == wcscmp(prop, NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY))
                {
                    if (nullptr == out || cb < sizeof(DWORD))
                    {
                        return kFailure;
                    }
                    *reinterpret_cast<DWORD *>(out) = isolation;
                    if (pcb)
                    {
                        *pcb = sizeof(DWORD);
                    }
                    return ERROR_SUCCESS;
                }
                if (0 == wcscmp(prop, NCRYPT_LENGTH_PROPERTY))
                {
                    if (nullptr == out || cb < sizeof(DWORD))
                    {
                        return kFailure;
                    }
                    *reinterpret_cast<DWORD *>(out) = key_bits;
                    if (pcb)
                    {
                        *pcb = sizeof(DWORD);
                    }
                    return ERROR_SUCCESS;
                }
                return kFailure;
            }));
}

// Makes NCryptExportKey return a well-formed P-256 public-key blob.
void InstallExportSuccess()
{
    EXPECT_MODULE_FUNC_CALL(NCryptExportKey, _, _, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(Invoke([](NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc *, PBYTE out, DWORD cb,
                                  DWORD *pcb, DWORD) -> SECURITY_STATUS {
            if (nullptr == out)
            {
                if (pcb)
                {
                    *pcb = kP256PublicBlobBytes;
                }
                return ERROR_SUCCESS;
            }
            if (cb < kP256PublicBlobBytes)
            {
                return static_cast<SECURITY_STATUS>(NTE_BUFFER_TOO_SMALL);
            }
            auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(out);
            header->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            header->cbKey = kP256KeyBytes;
            std::memset(out + sizeof(BCRYPT_ECCKEY_BLOB), 0x02, 2 * kP256KeyBytes);
            if (pcb)
            {
                *pcb = kP256PublicBlobBytes;
            }
            return ERROR_SUCCESS;
        }));
}

// Makes NCryptSignHash return a fixed-size raw r||s signature.
void InstallSignSuccess()
{
    EXPECT_MODULE_FUNC_CALL(NCryptSignHash, _, _, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(Invoke([](NCRYPT_KEY_HANDLE, VOID *, PBYTE, DWORD, PBYTE out, DWORD cb, DWORD *pcb,
                                  DWORD) -> SECURITY_STATUS {
            if (nullptr == out)
            {
                if (pcb)
                {
                    *pcb = kP256RawSigBytes;
                }
                return ERROR_SUCCESS;
            }
            if (cb < kP256RawSigBytes)
            {
                return static_cast<SECURITY_STATUS>(NTE_BUFFER_TOO_SMALL);
            }
            std::memset(out, 0x01, kP256RawSigBytes);
            if (pcb)
            {
                *pcb = kP256RawSigBytes;
            }
            return ERROR_SUCCESS;
        }));
}

// Drives the Windows backend through mocked NCrypt calls. Defaults describe a host
// where the key does not yet exist and every NCrypt call succeeds; each test narrows
// the one behavior it is about. Expectations are restored and verified per test so the
// real-hardware tests in the same binary are unaffected.
class WindowsNcryptMock : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(DoAll(SetArgPointee<0>(kFakeProvider), Return(ERROR_SUCCESS)));

        // No key exists yet, so the existence check in create_key finds nothing.
        EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _).Times(AnyNumber()).WillRepeatedly(Return(kNotFound));

        EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));

        EXPECT_MODULE_FUNC_CALL(NCryptSetProperty, _, _, _, _, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptGetProperty, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(kFailure));
        EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, _, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptFreeObject, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptSignHash, _, _, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(kFailure));
        EXPECT_MODULE_FUNC_CALL(NCryptVerifySignature, _, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(kFailure));
        EXPECT_MODULE_FUNC_CALL(NCryptExportKey, _, _, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(kFailure));
        EXPECT_MODULE_FUNC_CALL(NCryptImportKey, _, _, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(DoAll(SetArgPointee<4>(kFakeKey), Return(ERROR_SUCCESS)));
    }

    void TearDown() override
    {
        RESTORE_MODULE_FUNC(NCryptOpenStorageProvider);
        RESTORE_MODULE_FUNC(NCryptOpenKey);
        RESTORE_MODULE_FUNC(NCryptCreatePersistedKey);
        RESTORE_MODULE_FUNC(NCryptSetProperty);
        RESTORE_MODULE_FUNC(NCryptFinalizeKey);
        RESTORE_MODULE_FUNC(NCryptGetProperty);
        RESTORE_MODULE_FUNC(NCryptDeleteKey);
        RESTORE_MODULE_FUNC(NCryptFreeObject);
        RESTORE_MODULE_FUNC(NCryptSignHash);
        RESTORE_MODULE_FUNC(NCryptVerifySignature);
        RESTORE_MODULE_FUNC(NCryptExportKey);
        RESTORE_MODULE_FUNC(NCryptImportKey);

        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptOpenStorageProvider);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptOpenKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptCreatePersistedKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptSetProperty);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptFinalizeKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptGetProperty);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptDeleteKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptFreeObject);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptSignHash);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptVerifySignature);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptExportKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptImportKey);
    }

    static std::unique_ptr<mpss::KeyPair> CreateOsKey()
    {
        return mpss::KeyPair::Create("mock_win32_key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os");
    }
};

// Scenario: the TPM-backed Platform Crypto Provider accepts the first create attempt.
// Expected behavior: create_key stops at the first tier and reports Hardware protection.
TEST_F(WindowsNcryptMock, CreateKeyTpmTierSucceedsReportsHardware)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Hardware, key->key_info().protection);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
}

// Scenario: the TPM tier fails to create but the VBS tier succeeds.
// Expected behavior: create_key falls back one tier and reports Mixed protection.
TEST_F(WindowsNcryptMock, CreateKeyTpmFailsVbsSucceedsReportsMixed)
{
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .WillOnce(Return(kFailure)) // TPM tier
        .WillRepeatedly(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Mixed, key->key_info().protection);
    EXPECT_EQ("Virtualization Based Security", std::string(key->key_info().storage_description));
}

// Scenario: both the TPM and VBS tiers fail but the plain software tier succeeds.
// Expected behavior: create_key falls back to the last tier and reports Software protection.
TEST_F(WindowsNcryptMock, CreateKeyFallsBackToSoftwareReportsSoftware)
{
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .WillOnce(Return(kFailure)) // TPM tier
        .WillOnce(Return(kFailure)) // VBS tier
        .WillRepeatedly(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Software, key->key_info().protection);
    EXPECT_EQ("Software Protection", std::string(key->key_info().storage_description));
}

// Scenario: every tier fails to create the persisted key.
// Expected behavior: create_key returns null and reports a combined error naming all three tiers.
TEST_F(WindowsNcryptMock, CreateKeyAllTiersFailReturnsNullWithCombinedError)
{
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _).WillRepeatedly(Return(kFailure));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_EQ(nullptr, key);
    const std::string error = mpss::get_error();
    EXPECT_THAT(error, HasSubstr("TPM Protection"));
    EXPECT_THAT(error, HasSubstr("Virtualization Based Security"));
    EXPECT_THAT(error, HasSubstr("Software Protection"));
}

// Scenario: the key is created but NCryptFinalizeKey fails on every tier.
// Expected behavior: create_key deletes each half-created key and returns null.
TEST_F(WindowsNcryptMock, CreateKeyFinalizeFailsDeletesHalfCreatedKey)
{
    EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _).WillRepeatedly(Return(kFailure));
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, kFakeKey, _).Times(AtLeast(1)).WillRepeatedly(Return(ERROR_SUCCESS));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_EQ(nullptr, key);
}

// Scenario: making the freshly-created key non-exportable fails.
// Expected behavior: create_key fails closed before finalizing and deletes the key.
TEST_F(WindowsNcryptMock, CreateKeySetExportPolicyFailsFailsClosed)
{
    EXPECT_MODULE_FUNC_CALL(NCryptSetProperty, _, _, _, _, _).WillRepeatedly(Return(kFailure));
    EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _).Times(0);
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, kFakeKey, _).Times(AtLeast(1)).WillRepeatedly(Return(ERROR_SUCCESS));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_EQ(nullptr, key);
}

// Scenario: opening a key that no provider holds.
// Expected behavior: open returns null.
TEST_F(WindowsNcryptMock, OpenKeyNotFoundReturnsNull)
{
    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_absent_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: no storage provider can be opened at all.
// Expected behavior: open returns null.
TEST_F(WindowsNcryptMock, OpenKeyProviderUnavailableReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _).WillRepeatedly(Return(kFailure));

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: a reopened key is found in the TPM provider.
// Expected behavior: open classifies it as Hardware / "TPM Protection".
TEST_F(WindowsNcryptMock, OpenKeyInTpmProviderReportsHardware)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P256_ALGORITHM, /* isolation */ 0, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Hardware, key->key_info().protection);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
}

// Scenario: a reopened key is not in the TPM provider but is VBS-isolated in the software KSP.
// Expected behavior: open classifies it as Mixed / "Virtualization Based Security".
TEST_F(WindowsNcryptMock, OpenKeyIsolatedReportsMixed)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(Return(kNotFound)) // TPM provider
        .WillRepeatedly(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P256_ALGORITHM, /* isolation */ 1, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Mixed, key->key_info().protection);
    EXPECT_EQ("Virtualization Based Security", std::string(key->key_info().storage_description));
}

// Scenario: a reopened key is a plain (non-isolated) key in the software KSP.
// Expected behavior: open classifies it as Software / "Software Protection".
TEST_F(WindowsNcryptMock, OpenKeyNonIsolatedReportsSoftware)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(Return(kNotFound)) // TPM provider
        .WillRepeatedly(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P256_ALGORITHM, /* isolation */ 0, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Software, key->key_info().protection);
    EXPECT_EQ("Software Protection", std::string(key->key_info().storage_description));
}

// Scenario: an open key reports an unrecognized algorithm name but a known key length.
// Expected behavior: open falls back to deducing the algorithm from the key length.
TEST_F(WindowsNcryptMock, OpenKeyUnknownAlgorithmDeducesFromKeyLength)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(L"UnrecognizedAlg", /* isolation */ 0, /* key_bits */ 384);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Hardware, key->key_info().protection);
}

// Scenario: the algorithm property read itself fails, but the key length is known.
// Expected behavior: open still deduces the algorithm from the key length.
TEST_F(WindowsNcryptMock, OpenKeyAlgorithmReadFailsDeducesFromKeyLength)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(/* alg_name */ nullptr, /* isolation */ 0, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
}

// Scenario: an open key has neither a recognized algorithm name nor a known key length.
// Expected behavior: open returns null.
TEST_F(WindowsNcryptMock, OpenKeyUnknownAlgorithmAndLengthReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(L"UnrecognizedAlg", /* isolation */ 0, /* key_bits */ 999);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: create is asked for an unsupported algorithm.
// Expected behavior: create returns null.
TEST_F(WindowsNcryptMock, CreateKeyUnsupportedAlgorithmReturnsNull)
{
    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create("mock_win32_key", mpss::Algorithm::unsupported, "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: create is asked for a key whose name is empty.
// Expected behavior: create returns null.
TEST_F(WindowsNcryptMock, CreateKeyEmptyNameReturnsNull)
{
    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create("", mpss::Algorithm::ecdsa_secp256r1_sha256, "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: finalize fails and deleting the half-created key also fails.
// Expected behavior: create frees the orphaned handle and returns null.
TEST_F(WindowsNcryptMock, CreateKeyFinalizeFailsDeleteFailsFreesHandle)
{
    EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _).WillRepeatedly(Return(kFailure));
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, _, _).WillRepeatedly(Return(kFailure));
    EXPECT_MODULE_FUNC_CALL(NCryptFreeObject, kFakeKey).Times(AtLeast(1)).WillRepeatedly(Return(ERROR_SUCCESS));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_EQ(nullptr, key);
}

// Scenario: create is asked for a key that already exists.
// Expected behavior: the existence check finds it and create returns null.
TEST_F(WindowsNcryptMock, CreateKeyExistingKeyReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P256_ALGORITHM, /* isolation */ 0, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    EXPECT_EQ(nullptr, key);
}

// Scenario: sign_hash is asked only for the signature size (empty output buffer).
// Expected behavior: it returns a nonzero size without touching NCrypt.
TEST_F(WindowsNcryptMock, SignHashEmptyBufferReturnsMaxSize)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    const std::array<std::byte, 32> hash{};
    EXPECT_GT(key->sign_hash(hash, {}), 0u);
}

// Scenario: the first NCryptSignHash (size query) fails.
// Expected behavior: sign_hash returns 0.
TEST_F(WindowsNcryptMock, SignHashSizeQueryFailsReturnsZero)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 128> sig{};
    EXPECT_EQ(0u, key->sign_hash(hash, sig));
}

// Scenario: NCryptSignHash returns a raw signature.
// Expected behavior: sign_hash DER-encodes it and returns the encoded size.
TEST_F(WindowsNcryptMock, SignHashSucceedsReturnsEncodedSignature)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);
    InstallSignSuccess();

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 128> sig{};
    EXPECT_GT(key->sign_hash(hash, sig), 0u);
}

// Scenario: verify is called with empty inputs.
// Expected behavior: it returns false.
TEST_F(WindowsNcryptMock, VerifyEmptyInputsReturnsFalse)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    EXPECT_FALSE(key->verify({}, {}));
}

// Scenario: verify is called with a hash of the wrong size.
// Expected behavior: it returns false.
TEST_F(WindowsNcryptMock, VerifyWrongHashSizeReturnsFalse)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    const std::array<std::byte, 16> hash{};
    const std::array<std::byte, 8> sig{};
    EXPECT_FALSE(key->verify(hash, sig));
}

// Scenario: verify is given a hash of the right size but a signature that does not decode.
// Expected behavior: it returns false before reaching NCryptVerifySignature.
TEST_F(WindowsNcryptMock, VerifyUndecodableSignatureReturnsFalse)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    const std::array<std::byte, 32> hash{};
    const std::array<std::byte, 4> bad_sig{std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    EXPECT_FALSE(key->verify(hash, bad_sig));
}

// Scenario: a signature produced by sign_hash is verified with a passing NCryptVerifySignature.
// Expected behavior: verify returns true.
TEST_F(WindowsNcryptMock, VerifyValidSignatureReturnsTrue)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);
    InstallSignSuccess();

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 128> sig_buf{};
    const std::size_t sig_len = key->sign_hash(hash, sig_buf);
    ASSERT_GT(sig_len, 0u);

    EXPECT_MODULE_FUNC_CALL(NCryptVerifySignature, _, _, _, _, _, _, _).WillRepeatedly(Return(ERROR_SUCCESS));
    EXPECT_TRUE(key->verify(hash, std::span<const std::byte>(sig_buf.data(), sig_len)));
}

// Scenario: extract_key is asked only for the public-key size (empty output buffer).
// Expected behavior: it returns a nonzero size without touching NCrypt.
TEST_F(WindowsNcryptMock, ExtractKeyEmptyBufferReturnsSize)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    EXPECT_GT(key->extract_key({}), 0u);
}

// Scenario: the first NCryptExportKey (size query) fails.
// Expected behavior: extract_key returns 0.
TEST_F(WindowsNcryptMock, ExtractKeyExportFailsReturnsZero)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    std::array<std::byte, 65> pub{};
    EXPECT_EQ(0u, key->extract_key(pub));
}

// Scenario: NCryptExportKey returns a blob whose magic does not match the curve.
// Expected behavior: extract_key rejects it and returns 0.
TEST_F(WindowsNcryptMock, ExtractKeyInvalidMagicReturnsZero)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    EXPECT_MODULE_FUNC_CALL(NCryptExportKey, _, _, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(Invoke([](NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc *, PBYTE out, DWORD cb,
                                  DWORD *pcb, DWORD) -> SECURITY_STATUS {
            if (nullptr == out)
            {
                if (pcb)
                {
                    *pcb = kP256PublicBlobBytes;
                }
                return ERROR_SUCCESS;
            }
            if (cb < kP256PublicBlobBytes)
            {
                return static_cast<SECURITY_STATUS>(NTE_BUFFER_TOO_SMALL);
            }
            auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(out);
            header->dwMagic = 0xDEADBEEF; // wrong magic
            header->cbKey = kP256KeyBytes;
            if (pcb)
            {
                *pcb = kP256PublicBlobBytes;
            }
            return ERROR_SUCCESS;
        }));

    std::array<std::byte, 65> pub{};
    EXPECT_EQ(0u, key->extract_key(pub));
}

// Scenario: NCryptExportKey returns a well-formed public-key blob.
// Expected behavior: extract_key returns the public key with the uncompressed-point prefix.
TEST_F(WindowsNcryptMock, ExtractKeySucceedsReturnsPublicKey)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);
    InstallExportSuccess();

    std::array<std::byte, 65> pub{};
    EXPECT_GT(key->extract_key(pub), 0u);
    EXPECT_EQ(std::byte{0x04}, pub[0]);
}

// Scenario: delete_key's NCryptDeleteKey succeeds.
// Expected behavior: delete_key returns true.
TEST_F(WindowsNcryptMock, DeleteKeySucceedsReturnsTrue)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    EXPECT_TRUE(key->delete_key());
}

// Scenario: delete_key's NCryptDeleteKey fails.
// Expected behavior: delete_key returns false.
TEST_F(WindowsNcryptMock, DeleteKeyFailsReturnsFalse)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, kFakeKey, _).WillRepeatedly(Return(kFailure));
    EXPECT_FALSE(key->delete_key());
}

// Scenario: the free verify() is called with empty inputs.
// Expected behavior: it returns false.
TEST_F(WindowsNcryptMock, VerifyFreeEmptyInputsReturnsFalse)
{
    EXPECT_FALSE(mpss::verify({}, {}, mpss::Algorithm::ecdsa_secp256r1_sha256, {}, "os"));
}

// Scenario: the free verify() is given a public key without the uncompressed-point prefix.
// Expected behavior: it rejects the key format and returns false.
TEST_F(WindowsNcryptMock, VerifyFreeBadPublicKeyFormatReturnsFalse)
{
    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 65> pub{};
    pub[0] = std::byte{0x02}; // not the 0x04 uncompressed indicator
    const std::array<std::byte, 8> sig{};

    EXPECT_FALSE(mpss::verify(hash, pub, mpss::Algorithm::ecdsa_secp256r1_sha256, sig, "os"));
}

// Scenario: the free verify() cannot import the supplied public key.
// Expected behavior: it returns false.
TEST_F(WindowsNcryptMock, VerifyFreeImportFailsReturnsFalse)
{
    EXPECT_MODULE_FUNC_CALL(NCryptImportKey, _, _, _, _, _, _, _, _).WillRepeatedly(Return(kFailure));

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 65> pub{};
    pub[0] = std::byte{0x04};
    const std::array<std::byte, 8> sig{};

    EXPECT_FALSE(mpss::verify(hash, pub, mpss::Algorithm::ecdsa_secp256r1_sha256, sig, "os"));
}

// Scenario: open is called with an empty key name.
// Expected behavior: it returns null without touching NCrypt.
TEST_F(WindowsNcryptMock, OpenKeyEmptyNameReturnsNull)
{
    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: opening a key fails with an error other than "not found".
// Expected behavior: open still returns null.
TEST_F(WindowsNcryptMock, OpenKeyNonNotFoundErrorReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _).WillRepeatedly(Return(kFailure));

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: a reopened key reports the P-384 algorithm by name.
// Expected behavior: open recognizes it and succeeds.
TEST_F(WindowsNcryptMock, OpenKeyRecognizesP384ByName)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P384_ALGORITHM, /* isolation */ 0, /* key_bits */ 384);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Hardware, key->key_info().protection);
}

// Scenario: a reopened key reports the P-521 algorithm by name.
// Expected behavior: open recognizes it and succeeds.
TEST_F(WindowsNcryptMock, OpenKeyRecognizesP521ByName)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P521_ALGORITHM, /* isolation */ 0, /* key_bits */ 521);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::KeyProtection::Hardware, key->key_info().protection);
}

// Scenario: sign_hash is given a hash whose length does not match the algorithm.
// Expected behavior: it returns 0.
TEST_F(WindowsNcryptMock, SignHashWrongHashSizeReturnsZero)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    const std::array<std::byte, 16> hash{};
    std::array<std::byte, 128> sig{};
    EXPECT_EQ(0u, key->sign_hash(hash, sig));
}

// Scenario: sign_hash is given a non-empty output buffer that is too small.
// Expected behavior: it returns 0.
TEST_F(WindowsNcryptMock, SignHashInsufficientBufferReturnsZero)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 4> sig{};
    EXPECT_EQ(0u, key->sign_hash(hash, sig));
}

// Scenario: extract_key is given a non-empty output buffer that is too small.
// Expected behavior: it returns 0.
TEST_F(WindowsNcryptMock, ExtractKeyInsufficientBufferReturnsZero)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    std::array<std::byte, 8> pub{};
    EXPECT_EQ(0u, key->extract_key(pub));
}

// Scenario: the free verify() is asked for an unsupported algorithm.
// Expected behavior: it returns false.
TEST_F(WindowsNcryptMock, VerifyFreeUnsupportedAlgorithmReturnsFalse)
{
    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 65> pub{};
    pub[0] = std::byte{0x04};
    const std::array<std::byte, 8> sig{};

    EXPECT_FALSE(mpss::verify(hash, pub, mpss::Algorithm::unsupported, sig, "os"));
}

// Scenario: the free verify() is given a hash of the wrong size.
// Expected behavior: it returns false.
TEST_F(WindowsNcryptMock, VerifyFreeWrongHashSizeReturnsFalse)
{
    const std::array<std::byte, 16> hash{};
    std::array<std::byte, 65> pub{};
    pub[0] = std::byte{0x04};
    const std::array<std::byte, 8> sig{};

    EXPECT_FALSE(mpss::verify(hash, pub, mpss::Algorithm::ecdsa_secp256r1_sha256, sig, "os"));
}

// Scenario: an opened key's algorithm and length property reads all fail.
// Expected behavior: the algorithm cannot be deduced and open returns null.
TEST_F(WindowsNcryptMock, OpenKeyAllPropertyReadsFailReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    // NCryptGetProperty keeps the SetUp default of failing for every property.

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: opening a provider succeeds but yields a null handle.
// Expected behavior: the backend treats it as a failure and open returns null.
TEST_F(WindowsNcryptMock, OpenKeyNullProviderHandleReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _)
        .WillRepeatedly(DoAll(SetArgPointee<0>(NCRYPT_PROV_HANDLE{0}), Return(ERROR_SUCCESS)));

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    EXPECT_EQ(nullptr, key);
}

} // namespace

int main(int argc, char *argv[])
{
    // Initializes the IAT-patching machinery; must outlive RUN_ALL_TESTS.
    const gmock_win32::init_scope gmock_win32_scope{};

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

#endif // _WIN32
