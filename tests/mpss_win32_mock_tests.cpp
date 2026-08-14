// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Deterministic coverage for Windows CNG key creation (TPM -> VBS -> software).
//
// Real hardware cannot exercise the fallbacks: a host either has a TPM or it does not, and nothing
// makes a working provider fail. gmock-win32 intercepts the NCrypt calls so each provider can be
// failed on demand. Its import-table patching only reaches the executable it runs in, hence a
// separate executable linked against the static backend and omitting the OpenSSL provider, whose
// algorithm probing clashes with the process-global patching.

#ifdef _WIN32

#include "mpss/key_info.h"
#include "mpss/key_policy.h"
#include "mpss/mpss.h"
#include <cstring>
#include <cwchar>
#include <gmock-win32.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include <Windows.h>
#include <ncrypt.h>

using ::testing::_;
using ::testing::AnyNumber;
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

namespace
{

constexpr NCRYPT_PROV_HANDLE tpm_provider_handle = 0x1001;
constexpr NCRYPT_PROV_HANDLE ksp_provider_handle = 0x1002;
constexpr NCRYPT_KEY_HANDLE fake_key_handle = 0x2001;
constexpr SECURITY_STATUS status_not_found = static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET);
constexpr SECURITY_STATUS status_failure = static_cast<SECURITY_STATUS>(NTE_FAIL);

// Mirrors the backend's own fallback so the tests build against older SDKs.
#ifdef NCRYPT_REQUIRE_VBS_FLAG
constexpr DWORD require_vbs_flag = NCRYPT_REQUIRE_VBS_FLAG;
#else
constexpr DWORD require_vbs_flag = 0x00020000;
#endif

#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY
#define NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY L"Virtual Iso"
#endif

bool IsTpmProvider(LPCWSTR provider)
{
    return nullptr != provider && 0 == wcscmp(provider, MS_PLATFORM_KEY_STORAGE_PROVIDER);
}

// Defaults: the key does not exist and every provider works, so each test only fails what it is
// about.
class WindowsKeyCreation : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // A distinct handle per provider lets expectations tell them apart.
        EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([](NCRYPT_PROV_HANDLE *out, LPCWSTR provider, DWORD) -> SECURITY_STATUS {
                *out = IsTpmProvider(provider) ? tpm_provider_handle : ksp_provider_handle;
                return ERROR_SUCCESS;
            });

        // create_key's existence check must find nothing.
        EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(status_not_found));

        EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(DoAll(SetArgPointee<1>(fake_key_handle), Return(ERROR_SUCCESS)));

        EXPECT_MODULE_FUNC_CALL(NCryptSetProperty, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptGetProperty, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(status_failure));
        EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, _, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptFreeObject, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
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

        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptOpenStorageProvider);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptOpenKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptCreatePersistedKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptSetProperty);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptFinalizeKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptGetProperty);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptDeleteKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptFreeObject);
    }

    static void FailTpmProvider()
    {
        EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([](NCRYPT_PROV_HANDLE *out, LPCWSTR provider, DWORD) -> SECURITY_STATUS {
                if (IsTpmProvider(provider))
                {
                    return status_failure;
                }
                *out = ksp_provider_handle;
                return ERROR_SUCCESS;
            });
    }

    // VBS and software share a provider, so fail only the flagged create.
    static void FailVbsCreate()
    {
        EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([](NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *out, LPCWSTR, LPCWSTR, DWORD,
                                      DWORD flags) -> SECURITY_STATUS {
                if (0 != (flags & require_vbs_flag))
                {
                    return status_failure;
                }
                *out = fake_key_handle;
                return ERROR_SUCCESS;
            });
    }

    static std::unique_ptr<mpss::KeyPair> CreateOsKey()
    {
        return mpss::KeyPair::Create("mock_win32_key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os");
    }

    static std::unique_ptr<mpss::KeyPair> OpenOsKey()
    {
        return mpss::KeyPair::Open("mock_win32_key", "os");
    }

    // Finds the key in one provider only, so a reopen resolves there.
    static void KeyLivesIn(NCRYPT_PROV_HANDLE holder)
    {
        EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(
                [holder](NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *out, LPCWSTR, DWORD, DWORD)
                    -> SECURITY_STATUS {
                    if (provider != holder)
                    {
                        return status_not_found;
                    }
                    *out = fake_key_handle;
                    return ERROR_SUCCESS;
                });
    }

    // Answers the property queries a reopen makes: algorithm, key length, and VBS isolation.
    static void AnswerKeyProperties(bool virtually_isolated)
    {
        EXPECT_MODULE_FUNC_CALL(NCryptGetProperty, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([virtually_isolated](NCRYPT_HANDLE, LPCWSTR property, PBYTE out, DWORD size,
                                                        DWORD *written, DWORD) -> SECURITY_STATUS {
                if (nullptr == property || nullptr == written)
                {
                    return status_failure;
                }

                if (0 == wcscmp(property, NCRYPT_ALGORITHM_PROPERTY))
                {
                    const std::wstring algorithm = NCRYPT_ECDSA_P256_ALGORITHM;
                    const DWORD bytes = static_cast<DWORD>((algorithm.size() + 1) * sizeof(wchar_t));
                    *written = bytes;
                    if (nullptr == out)
                    {
                        return ERROR_SUCCESS;
                    }
                    if (bytes > size)
                    {
                        return status_failure;
                    }
                    std::memcpy(out, algorithm.c_str(), bytes);
                    return ERROR_SUCCESS;
                }

                if (0 == wcscmp(property, NCRYPT_LENGTH_PROPERTY))
                {
                    if (nullptr == out || sizeof(DWORD) > size)
                    {
                        return status_failure;
                    }
                    *reinterpret_cast<DWORD *>(out) = 256;
                    *written = sizeof(DWORD);
                    return ERROR_SUCCESS;
                }

                if (0 == wcscmp(property, NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY))
                {
                    if (!virtually_isolated || nullptr == out || sizeof(DWORD) > size)
                    {
                        return status_failure;
                    }
                    *reinterpret_cast<DWORD *>(out) = 1;
                    *written = sizeof(DWORD);
                    return ERROR_SUCCESS;
                }

                return status_failure;
            });
    }

    bool export_policy_cleared_before_finalize = false;
    bool finalized = false;

    // Records whether the export policy was cleared while the key was still unfinalized.
    void WatchExportPolicy()
    {
        EXPECT_MODULE_FUNC_CALL(NCryptSetProperty, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(
                [this](NCRYPT_HANDLE, LPCWSTR property, PBYTE value, DWORD size, DWORD) -> SECURITY_STATUS {
                    if (nullptr != property && 0 == wcscmp(property, NCRYPT_EXPORT_POLICY_PROPERTY) &&
                        nullptr != value && sizeof(DWORD) == size && 0 == *reinterpret_cast<DWORD *>(value) &&
                        !finalized)
                    {
                        export_policy_cleared_before_finalize = true;
                    }
                    return ERROR_SUCCESS;
                });

        EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([this](NCRYPT_KEY_HANDLE, DWORD) -> SECURITY_STATUS {
                finalized = true;
                return ERROR_SUCCESS;
            });
    }

};

// Scenario: the TPM-backed platform provider accepts the create.
// Expected behavior: the key reports TPM protection and is hardware-backed.
TEST_F(WindowsKeyCreation, TpmProviderReportsTpmProtection)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
    EXPECT_TRUE(key->key_info().is_hardware_backed);
}

// Scenario: the host has no TPM, so the platform provider cannot be opened, but VBS is available.
// Expected behavior: the create falls back to VBS and reports it as hardware-backed.
TEST_F(WindowsKeyCreation, TpmUnavailableFallsBackToVbs)
{
    FailTpmProvider();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Virtualization Based Security", std::string(key->key_info().storage_description));
    EXPECT_TRUE(key->key_info().is_hardware_backed);
}

// Scenario: neither the TPM nor VBS is available.
// Expected behavior: the create succeeds on software and reports itself as software-backed.
TEST_F(WindowsKeyCreation, TpmAndVbsUnavailableFallBackToSoftware)
{
    FailTpmProvider();
    FailVbsCreate();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Software Protection", std::string(key->key_info().storage_description));
    EXPECT_FALSE(key->key_info().is_hardware_backed);
}

// Scenario: a caller asks for a key on a host with no hardware-isolated provider.
// Expected behavior: success with a software key; the caller must inspect is_hardware_backed to
// notice the downgrade.
TEST_F(WindowsKeyCreation, SoftwareFallbackSucceedsWithoutSignalingDowngrade)
{
    FailTpmProvider();
    FailVbsCreate();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_FALSE(mpss::has_error()) << "a silent downgrade left an error set: " << mpss::get_error();
    EXPECT_FALSE(key->key_info().is_hardware_backed);
}

// Scenario: every provider fails.
// Expected behavior: no key is returned and the error names all three providers that were tried.
TEST_F(WindowsKeyCreation, AllProvidersFailReportEveryFailure)
{
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(Return(status_failure));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_EQ(nullptr, key);
    const std::string error = mpss::get_error();
    EXPECT_THAT(error, HasSubstr("TPM Protection"));
    EXPECT_THAT(error, HasSubstr("Virtualization Based Security"));
    EXPECT_THAT(error, HasSubstr("Software Protection"));
}

// Scenario: an earlier provider sets a thread-local error before a later one succeeds.
// Expected behavior: the successful create leaves no error behind.
TEST_F(WindowsKeyCreation, SuccessfulFallbackClearsEarlierProviderError)
{
    FailTpmProvider();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_FALSE(mpss::has_error()) << "successful create left a stale error: " << mpss::get_error();
}

// Scenario: the TPM-backed provider creates the key.
// Expected behavior: the export policy is cleared before the key is finalized.
TEST_F(WindowsKeyCreation, TpmProviderMarksTheKeyNonExportable)
{
    WatchExportPolicy();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_TRUE(export_policy_cleared_before_finalize);
    EXPECT_TRUE(finalized);
}

// Scenario: the TPM is unavailable, so VBS creates the key.
// Expected behavior: the export policy is cleared before the key is finalized.
TEST_F(WindowsKeyCreation, VbsProviderMarksTheKeyNonExportable)
{
    FailTpmProvider();
    WatchExportPolicy();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_TRUE(export_policy_cleared_before_finalize);
    EXPECT_TRUE(finalized);
}

// Scenario: neither the TPM nor VBS is available, so software creates the key.
// Expected behavior: the export policy is cleared before the key is finalized.
TEST_F(WindowsKeyCreation, SoftwareProviderMarksTheKeyNonExportable)
{
    FailTpmProvider();
    FailVbsCreate();
    WatchExportPolicy();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_TRUE(export_policy_cleared_before_finalize);
    EXPECT_TRUE(finalized);
}

// Scenario: the key is reopened by name and the TPM provider holds it.
// Expected behavior: the reopened key reports TPM protection and is hardware-backed.
TEST_F(WindowsKeyCreation, ReopenFromTpmReportsTpmProtection)
{
    KeyLivesIn(tpm_provider_handle);
    AnswerKeyProperties(false);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
    EXPECT_TRUE(key->key_info().is_hardware_backed);
}

// Scenario: the TPM does not hold the key, and the one in the software KSP is VBS-isolated.
// Expected behavior: the reopened key reports VBS and is hardware-backed.
TEST_F(WindowsKeyCreation, ReopenFromVbsReportsVirtualizationBasedSecurity)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(true);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Virtualization Based Security", std::string(key->key_info().storage_description));
    EXPECT_TRUE(key->key_info().is_hardware_backed);
}

// Scenario: the key lives in the software KSP and is not VBS-isolated.
// Expected behavior: the reopened key reports software protection rather than claiming isolation.
TEST_F(WindowsKeyCreation, ReopenFromSoftwareReportsSoftwareProtection)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(false);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Software Protection", std::string(key->key_info().storage_description));
    EXPECT_FALSE(key->key_info().is_hardware_backed);
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
