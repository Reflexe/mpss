// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// These tests use gmock-win32 to intercept the NCrypt free functions the Windows backend calls, so
// paths that cannot be provoked on real hardware (an absent TPM, a finalize failure, a delete that
// itself fails) are exercised deterministically. That matters here because CI runners have no TPM:
// without these mocks the Windows backend would be entirely unexercised there.
//
// IAT patching only reaches the executable it runs in, so this is its own executable linked against
// the static backend; it deliberately does not link the OpenSSL provider, whose algorithm-probing
// path conflicts with gmock-win32's process-global patching.

#if defined(_WIN32)

#include "mpss/key_info.h"
#include "mpss/key_policy.h"
#include "mpss/mpss.h"
#include "mpss/security_type.h"
#include <array>
#include <cstring>
#include <cwchar>
#include <gmock-win32.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <vector>

#include <Windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

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
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptFinalizeKey, NCRYPT_KEY_HANDLE, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptGetProperty, NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD *, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptDeleteKey, NCRYPT_KEY_HANDLE, DWORD);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptFreeObject, NCRYPT_HANDLE);
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptSignHash, NCRYPT_KEY_HANDLE, VOID *, PBYTE, DWORD, PBYTE, DWORD, DWORD *,
                  DWORD);
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

// Serves the property reads that open_key performs: the algorithm name and the key length. A null
// algorithm name makes the algorithm read fail.
void InstallGetProperty(const wchar_t *alg_name, DWORD key_bits)
{
    EXPECT_MODULE_FUNC_CALL(NCryptGetProperty, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(Invoke([alg_name, key_bits](NCRYPT_HANDLE, LPCWSTR prop, PBYTE out, DWORD cb, DWORD *pcb,
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
        .WillRepeatedly(Invoke([](NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc *, PBYTE out,
                                  DWORD cb, DWORD *pcb, DWORD) -> SECURITY_STATUS {
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

// Drives the Windows backend through mocked NCrypt calls. Defaults describe a host where the key
// does not yet exist and every NCrypt call succeeds; each test narrows the one behavior it is
// about. Expectations are restored and verified per test.
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

// Scenario: the TPM-backed Platform Crypto Provider accepts the create.
// Expected behavior: the key is created and reports the hardware tier.
TEST_F(WindowsNcryptMock, CreateKeyReportsHardware)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
}

// Scenario: a caller requires at most the hardware tier, which the TPM provides.
// Expected behavior: creation succeeds; the floor changes nothing.
TEST_F(WindowsNcryptMock, CreateKeyAtHardwareFloorSucceeds)
{
    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(
        "mock_win32_key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os", mpss::KeyPolicy::none,
        mpss::SecurityType::hardware);

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
}

// Scenario: a caller requires a secure element, which Windows never provides.
// Expected behavior: the request is pruned before any provider is touched, so no key is ever
// persisted and nothing has to be cleaned up.
TEST_F(WindowsNcryptMock, CreateKeySecureElementFloorFailsBeforeTouchingProvider)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _).Times(0);
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _).Times(0);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(
        "mock_win32_key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os", mpss::KeyPolicy::none,
        mpss::SecurityType::secure_element);

    ASSERT_EQ(nullptr, key);
    EXPECT_THAT(mpss::get_error(), HasSubstr("secure_element"));
}

// Scenario: a caller requires a secure element when opening an existing key.
// Expected behavior: the open fails without touching the provider.
TEST_F(WindowsNcryptMock, OpenKeySecureElementFloorFails)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _).Times(0);

    std::unique_ptr<mpss::KeyPair> key =
        mpss::KeyPair::Open("mock_win32_key", "os", mpss::SecurityType::secure_element);

    EXPECT_EQ(nullptr, key);
}

// Scenario: the Platform KSP cannot create the persisted key, which is what a host without a
// usable TPM looks like.
// Expected behavior: create returns null and the error names the provider that failed.
TEST_F(WindowsNcryptMock, CreateKeyProviderFailsReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _).WillRepeatedly(Return(kFailure));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_EQ(nullptr, key);
    EXPECT_THAT(mpss::get_error(), HasSubstr("TPM Protection"));
}

// Scenario: the key is persisted but NCryptFinalizeKey fails.
// Expected behavior: the half-created key is deleted rather than left behind, and create fails.
TEST_F(WindowsNcryptMock, CreateKeyFinalizeFailsDeletesHalfCreatedKey)
{
    EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _).WillRepeatedly(Return(kFailure));
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, kFakeKey, _).Times(AtLeast(1)).WillRepeatedly(Return(ERROR_SUCCESS));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_EQ(nullptr, key);
}

// Scenario: finalize fails and deleting the half-created key also fails.
// Expected behavior: create still fails, and the orphaned handle is closed rather than leaked.
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
    InstallGetProperty(NCRYPT_ECDSA_P256_ALGORITHM, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

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

// Scenario: opening a key the provider does not hold.
// Expected behavior: open returns null.
TEST_F(WindowsNcryptMock, OpenKeyNotFoundReturnsNull)
{
    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_absent_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: the storage provider cannot be opened at all.
// Expected behavior: open returns null.
TEST_F(WindowsNcryptMock, OpenKeyProviderUnavailableReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _).WillRepeatedly(Return(kFailure));

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: a reopened key is found in the Platform KSP.
// Expected behavior: open classifies it as hardware / "TPM Protection".
TEST_F(WindowsNcryptMock, OpenKeyReportsHardware)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P256_ALGORITHM, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
}

// Scenario: an open key reports an unrecognized algorithm name but a known key length.
// Expected behavior: open falls back to deducing the algorithm from the key length.
TEST_F(WindowsNcryptMock, OpenKeyUnknownAlgorithmDeducesFromKeyLength)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(L"UnrecognizedAlg", /* key_bits */ 384);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
}

// Scenario: the algorithm property read itself fails, but the key length is known.
// Expected behavior: open still deduces the algorithm from the key length.
TEST_F(WindowsNcryptMock, OpenKeyAlgorithmReadFailsDeducesFromKeyLength)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(/* alg_name */ nullptr, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
}

// Scenario: an open key has neither a recognized algorithm name nor a known key length.
// Expected behavior: open returns null.
TEST_F(WindowsNcryptMock, OpenKeyUnknownAlgorithmAndLengthReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(L"UnrecognizedAlg", /* key_bits */ 999);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    EXPECT_EQ(nullptr, key);
}

// Scenario: a reopened key reports the P-384 algorithm by name.
// Expected behavior: open recognizes it and succeeds.
TEST_F(WindowsNcryptMock, OpenKeyRecognizesP384ByName)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P384_ALGORITHM, /* key_bits */ 384);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
}

// Scenario: a reopened key reports the P-521 algorithm by name.
// Expected behavior: open recognizes it and succeeds.
TEST_F(WindowsNcryptMock, OpenKeyRecognizesP521ByName)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P521_ALGORITHM, /* key_bits */ 521);

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
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
        .WillRepeatedly(Invoke([](NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc *, PBYTE out,
                                  DWORD cb, DWORD *pcb, DWORD) -> SECURITY_STATUS {
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

// Scenario: extract_key is given a non-empty output buffer that is too small.
// Expected behavior: it returns 0.
TEST_F(WindowsNcryptMock, ExtractKeyInsufficientBufferReturnsZero)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    std::array<std::byte, 8> pub{};
    EXPECT_EQ(0u, key->extract_key(pub));
}

// Scenario: delete_key's NCryptDeleteKey succeeds.
// Expected behavior: delete_key returns true.
TEST_F(WindowsNcryptMock, DeleteKeySucceedsReturnsTrue)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    EXPECT_TRUE(key->delete_key());
}

// Scenario: a successful NCryptDeleteKey has already freed the handle.
// Expected behavior: the key pair relinquishes it instead of closing it a second time.
TEST_F(WindowsNcryptMock, DeleteKeyDoesNotFreeTheHandleAgain)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);

    EXPECT_MODULE_FUNC_CALL(NCryptFreeObject, kFakeKey).Times(0);
    EXPECT_TRUE(key->delete_key());
    key.reset();
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

// Scenario: create is asked for a key policy the Windows backend does not implement.
// Expected behavior: create returns null without touching the provider.
TEST_F(WindowsNcryptMock, CreateKeyUnsupportedPolicyReturnsNull)
{
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _).Times(0);

    std::unique_ptr<mpss::KeyPair> key =
        mpss::KeyPair::Create("mock_win32_key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os",
                              mpss::KeyPolicy::apple_secure_enclave_user_presence);

    EXPECT_EQ(nullptr, key);
}

// Scenario: an existing key is opened with a floor the TPM tier satisfies.
// Expected behavior: the floor is threaded through open and the key is returned.
TEST_F(WindowsNcryptMock, OpenKeyAtHardwareFloorSucceeds)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    InstallGetProperty(NCRYPT_ECDSA_P256_ALGORITHM, /* key_bits */ 256);

    std::unique_ptr<mpss::KeyPair> key =
        mpss::KeyPair::Open("mock_win32_key", "os", mpss::SecurityType::hardware);

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
}

// Scenario: the free verify() is given a well-formed public key and a decodable signature that
// NCryptVerifySignature accepts.
// Expected behavior: it imports the key through the software KSP and returns true.
TEST_F(WindowsNcryptMock, VerifyFreeValidSignatureReturnsTrue)
{
    // Produce a signature in the encoding the free verify() expects.
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);
    InstallSignSuccess();

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 128> sig_buf{};
    const std::size_t sig_len = key->sign_hash(hash, sig_buf);
    ASSERT_GT(sig_len, 0u);

    std::array<std::byte, 65> pub{};
    pub[0] = std::byte{0x04};

    EXPECT_MODULE_FUNC_CALL(NCryptVerifySignature, _, _, _, _, _, _, _).WillRepeatedly(Return(ERROR_SUCCESS));
    EXPECT_TRUE(mpss::verify(hash, pub, mpss::Algorithm::ecdsa_secp256r1_sha256,
                             std::span<const std::byte>(sig_buf.data(), sig_len), "os"));
}

// Scenario: the free verify() reaches NCryptVerifySignature and the signature is rejected.
// Expected behavior: it returns false rather than reporting a hard error.
TEST_F(WindowsNcryptMock, VerifyFreeRejectedSignatureReturnsFalse)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();
    ASSERT_NE(nullptr, key);
    InstallSignSuccess();

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 128> sig_buf{};
    const std::size_t sig_len = key->sign_hash(hash, sig_buf);
    ASSERT_GT(sig_len, 0u);

    std::array<std::byte, 65> pub{};
    pub[0] = std::byte{0x04};

    EXPECT_MODULE_FUNC_CALL(NCryptVerifySignature, _, _, _, _, _, _, _).WillRepeatedly(Return(kFailure));
    EXPECT_FALSE(mpss::verify(hash, pub, mpss::Algorithm::ecdsa_secp256r1_sha256,
                              std::span<const std::byte>(sig_buf.data(), sig_len), "os"));
}

// Scenario: the algorithm property's size query succeeds but the follow-up read of the value
// fails, which is a different branch from the size query failing outright.
// Expected behavior: open falls back to deducing the algorithm from the key length.
TEST_F(WindowsNcryptMock, OpenKeyAlgorithmValueReadFailsDeducesFromKeyLength)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
        .WillOnce(DoAll(SetArgPointee<1>(kFakeKey), Return(ERROR_SUCCESS)));
    EXPECT_MODULE_FUNC_CALL(NCryptGetProperty, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(Invoke([](NCRYPT_HANDLE, LPCWSTR prop, PBYTE out, DWORD cb, DWORD *pcb,
                                  DWORD) -> SECURITY_STATUS {
            if (0 == wcscmp(prop, NCRYPT_ALGORITHM_PROPERTY))
            {
                if (nullptr == out)
                {
                    // Report a size, so the backend proceeds to read the value.
                    if (pcb)
                    {
                        *pcb = 64;
                    }
                    return ERROR_SUCCESS;
                }
                return kFailure; // ... and then fail the value read.
            }
            if (0 == wcscmp(prop, NCRYPT_LENGTH_PROPERTY))
            {
                if (nullptr == out || cb < sizeof(DWORD))
                {
                    return kFailure;
                }
                *reinterpret_cast<DWORD *>(out) = 256;
                if (pcb)
                {
                    *pcb = sizeof(DWORD);
                }
                return ERROR_SUCCESS;
            }
            return kFailure;
        }));

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open("mock_win32_key", "os");

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::SecurityType::hardware, key->key_info().security_type);
}

// Scenario: NCryptImportKey reports success but leaves the output handle empty.
// Expected behavior: the free verify() treats it as a failure instead of using a null handle.
TEST_F(WindowsNcryptMock, VerifyFreeImportYieldsNullHandleReturnsFalse)
{
    EXPECT_MODULE_FUNC_CALL(NCryptImportKey, _, _, _, _, _, _, _, _)
        .WillRepeatedly(DoAll(SetArgPointee<4>(NCRYPT_KEY_HANDLE{0}), Return(ERROR_SUCCESS)));

    const std::array<std::byte, 32> hash{};
    std::array<std::byte, 65> pub{};
    pub[0] = std::byte{0x04};
    const std::array<std::byte, 8> sig{};

    EXPECT_FALSE(mpss::verify(hash, pub, mpss::Algorithm::ecdsa_secp256r1_sha256, sig, "os"));
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
