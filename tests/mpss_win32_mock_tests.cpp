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
MOCK_STDCALL_FUNC(SECURITY_STATUS, NCryptSignHash, NCRYPT_KEY_HANDLE, VOID *, PBYTE, DWORD, PBYTE, DWORD, DWORD *,
                  DWORD);

namespace
{

constexpr NCRYPT_PROV_HANDLE tpm_provider_handle = 0x1001;
constexpr NCRYPT_PROV_HANDLE ksp_provider_handle = 0x1002;
constexpr NCRYPT_KEY_HANDLE tpm_key_handle = 0x2001;
constexpr NCRYPT_KEY_HANDLE ksp_key_handle = 0x2002;
constexpr NCRYPT_KEY_HANDLE software_key_handle = 0x2003;
constexpr SECURITY_STATUS status_not_found = static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET);
constexpr SECURITY_STATUS status_failure = static_cast<SECURITY_STATUS>(NTE_FAIL);
constexpr SECURITY_STATUS status_not_supported = static_cast<SECURITY_STATUS>(NTE_NOT_SUPPORTED);
constexpr SECURITY_STATUS status_exists = static_cast<SECURITY_STATUS>(NTE_EXISTS);

// What a key without a named group reports when asked for one. Measured on Windows: a key created
// through a suffixed algorithm identifier answers NTE_NOT_FOUND, not NTE_NOT_SUPPORTED.
constexpr SECURITY_STATUS status_property_absent = static_cast<SECURITY_STATUS>(NTE_NOT_FOUND);

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
            .WillRepeatedly([](NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *out, LPCWSTR, LPCWSTR, DWORD,
                               DWORD flags) -> SECURITY_STATUS {
                *out = tpm_provider_handle == provider
                           ? tpm_key_handle
                           : (0 != (flags & require_vbs_flag) ? ksp_key_handle : software_key_handle);
                return ERROR_SUCCESS;
            });

        EXPECT_MODULE_FUNC_CALL(NCryptSetProperty, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptFinalizeKey, _, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));

        // A key created through the require_vbs provider reports that it is isolated. Tests that
        // care about a different answer install their own with AnswerKeyProperties.
        AnswerKeyProperties(Isolation::automatic);

        EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, _, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptFreeObject, _).Times(AnyNumber()).WillRepeatedly(Return(ERROR_SUCCESS));
        EXPECT_MODULE_FUNC_CALL(NCryptSignHash, _, _, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([](NCRYPT_KEY_HANDLE, VOID *, PBYTE, DWORD, PBYTE output, DWORD,
                               DWORD *written, DWORD) -> SECURITY_STATUS {
                constexpr DWORD signature_size = 64;
                *written = signature_size;
                if (nullptr != output)
                {
                    std::memset(output, 0, signature_size);
                }
                return ERROR_SUCCESS;
            });
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

        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptOpenStorageProvider);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptOpenKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptCreatePersistedKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptSetProperty);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptFinalizeKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptGetProperty);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptDeleteKey);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptFreeObject);
        VERIFY_AND_CLEAR_MODULE_FUNC(NCryptSignHash);
    }

    static void FailTpmProvider()
    {
        EXPECT_MODULE_FUNC_CALL(NCryptOpenStorageProvider, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([](NCRYPT_PROV_HANDLE *out, LPCWSTR provider, DWORD) -> SECURITY_STATUS {
                if (IsTpmProvider(provider))
                {
                    return status_not_supported;
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
                    return status_not_supported;
                }
                *out = software_key_handle;
                return ERROR_SUCCESS;
            });
    }

    static std::unique_ptr<mpss::KeyPair> CreateOsKey(
        mpss::IsolationLevel minimum_isolation = mpss::IsolationLevel::software)
    {
        return mpss::KeyPair::Create("mock_win32_key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os",
                                     mpss::KeyPolicy::none, minimum_isolation);
    }

    static std::unique_ptr<mpss::KeyPair> OpenOsKey(
        mpss::IsolationLevel minimum_isolation = mpss::IsolationLevel::software)
    {
        return mpss::KeyPair::Open("mock_win32_key", "os", minimum_isolation);
    }

    // Finds the key in one provider only, so a reopen resolves there.
    static void KeyLivesIn(NCRYPT_PROV_HANDLE holder)
    {
        EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([holder](NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *out, LPCWSTR, DWORD,
                                     DWORD) -> SECURITY_STATUS {
                if (provider != holder)
                {
                    return status_not_found;
                }
                *out = tpm_provider_handle == holder ? tpm_key_handle : ksp_key_handle;
                return ERROR_SUCCESS;
            });
    }

    // How NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY behaves for a key. All four cases occur on real
    // hardware, and they differ in the returned status, the DWORD value written, or both:
    //   isolated     -> ERROR_SUCCESS,     value 1  (software KSP key created with require_vbs)
    //   not_isolated -> ERROR_SUCCESS,     value 0  (ordinary software KSP key)
    //   read_fails   -> any other status,  no value
    enum class Isolation
    {
        automatic,
        isolated,
        not_isolated,
        read_fails
    };

    // Answers the property queries a reopen makes: algorithm, named group, VBS isolation and export
    // policy. The export policy defaults to what a key MPSS created reports.
    static void AnswerKeyProperties(Isolation isolation, SECURITY_STATUS export_status = ERROR_SUCCESS,
                                    DWORD export_policy = 0, std::wstring algorithm_name = NCRYPT_ECDSA_P256_ALGORITHM,
                                    std::wstring group_name = {})
    {
        EXPECT_MODULE_FUNC_CALL(NCryptGetProperty, _, _, _, _, _, _)
            .Times(AnyNumber())
            .WillRepeatedly([isolation, export_status, export_policy, algorithm_name = std::move(algorithm_name),
                             group_name = std::move(group_name)](NCRYPT_HANDLE handle, LPCWSTR property, PBYTE out,
                                                                 DWORD size, DWORD *written, DWORD) -> SECURITY_STATUS {
                if (nullptr == property || nullptr == written)
                {
                    return status_failure;
                }

                // Both string properties follow the same two-call protocol: a sizing call with a
                // null buffer, then the real read.
                auto answer_string = [out, size, written](const std::wstring &value) -> SECURITY_STATUS {
                    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
                    *written = bytes;
                    if (nullptr == out)
                    {
                        return ERROR_SUCCESS;
                    }
                    if (bytes > size)
                    {
                        return status_failure;
                    }
                    std::memcpy(out, value.c_str(), bytes);
                    return ERROR_SUCCESS;
                };

                if (0 == wcscmp(property, NCRYPT_ALGORITHM_PROPERTY))
                {
                    return answer_string(algorithm_name);
                }

                if (0 == wcscmp(property, NCRYPT_ECC_CURVE_NAME_PROPERTY))
                {
                    if (group_name.empty())
                    {
                        return status_property_absent;
                    }
                    return answer_string(group_name);
                }

                if (0 == wcscmp(property, NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY))
                {
                    const Isolation measured =
                        Isolation::automatic == isolation
                            ? (software_key_handle == handle ? Isolation::not_isolated : Isolation::isolated)
                            : isolation;
                    if (Isolation::read_fails == measured)
                    {
                        return status_failure;
                    }
                    if (nullptr == out || sizeof(DWORD) > size)
                    {
                        return status_failure;
                    }
                    *reinterpret_cast<DWORD *>(out) = Isolation::isolated == measured ? 1 : 0;
                    *written = sizeof(DWORD);
                    return ERROR_SUCCESS;
                }

                if (0 == wcscmp(property, NCRYPT_EXPORT_POLICY_PROPERTY))
                {
                    if (ERROR_SUCCESS != export_status)
                    {
                        return export_status;
                    }
                    if (nullptr == out || sizeof(DWORD) > size)
                    {
                        return status_failure;
                    }
                    *reinterpret_cast<DWORD *>(out) = export_policy;
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
            .WillRepeatedly([this](NCRYPT_HANDLE, LPCWSTR property, PBYTE value, DWORD size, DWORD) -> SECURITY_STATUS {
                if (nullptr != property && 0 == wcscmp(property, NCRYPT_EXPORT_POLICY_PROPERTY) && nullptr != value &&
                    sizeof(DWORD) == size && 0 == *reinterpret_cast<DWORD *>(value) && !finalized)
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
// Expected behavior: the key reports TPM protection at hardware isolation.
TEST_F(WindowsKeyCreation, TpmProviderReportsTpmProtection)
{
    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::hardware, key->key_info().isolation_level);
}

// Scenario: the host has no TPM, so the platform provider cannot be opened, but VBS is available.
// Expected behavior: the create falls back to VBS and reports mixed isolation.
TEST_F(WindowsKeyCreation, TpmUnavailableFallsBackToVbs)
{
    FailTpmProvider();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Virtualization Based Security", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::mixed, key->key_info().isolation_level);
}

// Scenario: neither the TPM nor VBS is available.
// Expected behavior: the create succeeds on software and reports software isolation.
TEST_F(WindowsKeyCreation, TpmAndVbsUnavailableFallBackToSoftware)
{
    FailTpmProvider();
    FailVbsCreate();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Software Protection", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::software, key->key_info().isolation_level);
}

// Scenario: a caller asks for a key on a host with no hardware-isolated provider.
// Expected behavior: success with a software key; the caller can inspect its concrete isolation level.
TEST_F(WindowsKeyCreation, SoftwareFallbackSucceedsWithoutSignalingDowngrade)
{
    FailTpmProvider();
    FailVbsCreate();

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_FALSE(mpss::has_error()) << "a silent downgrade left an error set: " << mpss::get_error();
    EXPECT_EQ(mpss::IsolationLevel::software, key->key_info().isolation_level);
}

// Scenario: every provider fails.
// Expected behavior: no key is returned and the error names all three providers that were tried.
TEST_F(WindowsKeyCreation, AllProvidersFailReportEveryFailure)
{
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly(Return(status_not_supported));

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
// Expected behavior: the reopened key reports TPM protection at hardware isolation.
TEST_F(WindowsKeyCreation, ReopenFromTpmReportsTpmProtection)
{
    KeyLivesIn(tpm_provider_handle);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("TPM Protection", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::hardware, key->key_info().isolation_level);
}

// Scenario: the TPM does not hold the key, and the one in the software KSP is VBS-isolated.
// Expected behavior: the reopened key reports VBS at mixed isolation.
TEST_F(WindowsKeyCreation, ReopenFromVbsReportsVirtualizationBasedSecurity)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::isolated);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Virtualization Based Security", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::mixed, key->key_info().isolation_level);
}

// Scenario: the key lives in the software KSP and is not VBS-isolated.
// Expected behavior: the reopened key reports software protection rather than claiming isolation.
TEST_F(WindowsKeyCreation, ReopenFromSoftwareReportsSoftwareProtection)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Software Protection", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::software, key->key_info().isolation_level);
}

// Scenario: an existing TPM key is opened with hardware and mixed minimum isolation.
// Expected behavior: both the equal and weaker minimum accept the hardware-isolated key.
TEST_F(WindowsKeyCreation, OpenAcceptsEqualAndStrongerIsolation)
{
    KeyLivesIn(tpm_provider_handle);

    std::unique_ptr<mpss::KeyPair> equal = OpenOsKey(mpss::IsolationLevel::hardware);
    std::unique_ptr<mpss::KeyPair> stronger = OpenOsKey(mpss::IsolationLevel::mixed);

    ASSERT_NE(nullptr, equal);
    ASSERT_NE(nullptr, stronger);
    EXPECT_EQ(mpss::IsolationLevel::hardware, equal->key_info().isolation_level);
    EXPECT_EQ(mpss::IsolationLevel::hardware, stronger->key_info().isolation_level);
}

// Scenario: an existing VBS key is opened with mixed minimum isolation.
// Expected behavior: the equal minimum accepts the mixed-isolation key.
TEST_F(WindowsKeyCreation, OpenAcceptsEqualVbsIsolation)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::isolated);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey(mpss::IsolationLevel::mixed);

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::IsolationLevel::mixed, key->key_info().isolation_level);
}

// Scenario: a software key is opened with mixed minimum isolation and then reopened without a constraint.
// Expected behavior: the constrained Open releases its handle without deleting the persisted key.
TEST_F(WindowsKeyCreation, UnderqualifiedOpenReleasesWithoutDeleting)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated);
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, ksp_key_handle, _).Times(0);
    EXPECT_MODULE_FUNC_CALL(NCryptFreeObject, ksp_key_handle).Times(2).WillRepeatedly(Return(ERROR_SUCCESS));

    std::unique_ptr<mpss::KeyPair> rejected = OpenOsKey(mpss::IsolationLevel::mixed);
    EXPECT_EQ(nullptr, rejected);
    EXPECT_THAT(mpss::get_error(), HasSubstr("minimum isolation"));

    std::unique_ptr<mpss::KeyPair> reopened = OpenOsKey();
    ASSERT_NE(nullptr, reopened);
    EXPECT_EQ(mpss::IsolationLevel::software, reopened->key_info().isolation_level);
}

// Scenario: creation requests hardware, mixed, and software minimum isolation in turn.
// Expected behavior: each request tries only its qualifying candidates in strongest-first order.
TEST_F(WindowsKeyCreation, MinimumIsolationSelectsQualifyingCandidatesStrongestFirst)
{
    std::string attempts;
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(6)
        .WillRepeatedly([&attempts](NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *out, LPCWSTR, LPCWSTR, DWORD,
                                   DWORD flags) -> SECURITY_STATUS {
            if (tpm_provider_handle == provider)
            {
                attempts += 'T';
                if (1 == attempts.size())
                {
                    *out = tpm_key_handle;
                    return ERROR_SUCCESS;
                }
                return status_not_supported;
            }
            if (0 != (flags & require_vbs_flag))
            {
                attempts += 'V';
                if (5 == attempts.size())
                {
                    return status_not_supported;
                }
                *out = ksp_key_handle;
                return ERROR_SUCCESS;
            }
            attempts += 'S';
            *out = software_key_handle;
            return ERROR_SUCCESS;
        });

    std::unique_ptr<mpss::KeyPair> hardware = CreateOsKey(mpss::IsolationLevel::hardware);
    std::unique_ptr<mpss::KeyPair> mixed = CreateOsKey(mpss::IsolationLevel::mixed);
    std::unique_ptr<mpss::KeyPair> software = CreateOsKey();

    ASSERT_NE(nullptr, hardware);
    ASSERT_NE(nullptr, mixed);
    ASSERT_NE(nullptr, software);
    EXPECT_EQ(mpss::IsolationLevel::hardware, hardware->key_info().isolation_level);
    EXPECT_EQ(mpss::IsolationLevel::mixed, mixed->key_info().isolation_level);
    EXPECT_EQ(mpss::IsolationLevel::software, software->key_info().isolation_level);
    EXPECT_EQ("TTVTVS", attempts);
}
// Scenario: mixed availability is queried twice, then hardware availability is queried for the same algorithm.
// Expected behavior: the repeated default-backend query uses its positive cache entry, while the different minimum
// runs a distinct TPM-only constrained probe.
TEST_F(WindowsKeyCreation, AvailabilityUsesConstrainedCreationAndPositiveCache)
{
    int create_attempts = 0;
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(3)
        .WillRepeatedly([&create_attempts](NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *out, LPCWSTR, LPCWSTR,
                                          DWORD, DWORD flags) -> SECURITY_STATUS {
            ++create_attempts;
            if (tpm_provider_handle == provider)
            {
                return status_not_supported;
            }
            if (0 == (flags & require_vbs_flag))
            {
                return status_failure;
            }
            *out = ksp_key_handle;
            return ERROR_SUCCESS;
        });

    EXPECT_TRUE(mpss::is_algorithm_available(mpss::Algorithm::ecdsa_secp384r1_sha384,
                                             mpss::IsolationLevel::mixed));
    EXPECT_TRUE(mpss::is_algorithm_available(mpss::Algorithm::ecdsa_secp384r1_sha384,
                                             mpss::IsolationLevel::mixed));
    EXPECT_FALSE(mpss::is_algorithm_available(mpss::Algorithm::ecdsa_secp384r1_sha384,
                                              mpss::IsolationLevel::hardware));
    EXPECT_EQ(3, create_attempts);
}

// Scenario: a software-isolation availability probe fails on every Windows provider twice.
// Expected behavior: the negative result is not cached, so all three providers are retried.
TEST_F(WindowsKeyCreation, NegativeAvailabilityIsNotCached)
{
    int create_attempts = 0;
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(6)
        .WillRepeatedly([&create_attempts](NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *, LPCWSTR, LPCWSTR, DWORD,
                                           DWORD) -> SECURITY_STATUS {
            ++create_attempts;
            return status_not_supported;
        });

    EXPECT_FALSE(mpss::is_algorithm_available(mpss::Algorithm::ecdsa_secp256r1_sha256, "os"));
    EXPECT_FALSE(mpss::is_algorithm_available(mpss::Algorithm::ecdsa_secp256r1_sha256, "os"));
    EXPECT_EQ(6, create_attempts);
}

// Scenario: the key lives in the software KSP, but reading its isolation property fails outright.
// Expected behavior: the open fails and reports the error, rather than reporting a tier that was
// never established.
TEST_F(WindowsKeyCreation, ReopenWithUnreadableIsolationFailsRatherThanClaimingSoftware)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::read_fails);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
    EXPECT_THAT(mpss::get_error(), HasSubstr("virtual isolation"));
}

// Scenario: the TPM is unavailable, the VBS creation call succeeds, but the created key reports that
// it is not isolated.
// Expected behavior: the key is reported as software protected. A successful require_vbs call is not
// by itself evidence that isolation happened.
TEST_F(WindowsKeyCreation, VbsCreationThatIsNotIsolatedIsReportedAsSoftware)
{
    FailTpmProvider();
    AnswerKeyProperties(Isolation::not_isolated);

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Software Protection", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::software, key->key_info().isolation_level);
}

// Scenario: mixed isolation is required, but the newly created VBS candidate measures as software.
// Expected behavior: the underqualified key is deleted and never returned.
TEST_F(WindowsKeyCreation, UnderqualifiedNewKeyIsDeletedAndRejected)
{
    FailTpmProvider();
    AnswerKeyProperties(Isolation::not_isolated);
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, ksp_key_handle, _).Times(1).WillOnce(Return(ERROR_SUCCESS));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey(mpss::IsolationLevel::mixed);

    EXPECT_EQ(nullptr, key);
    EXPECT_THAT(mpss::get_error(), HasSubstr("below requested minimum"));
}

// Scenario: an underqualified newly created key cannot be deleted during mandatory cleanup.
// Expected behavior: no key is returned and the cleanup failure is reported.
TEST_F(WindowsKeyCreation, UnderqualifiedNewKeyCleanupFailureIsReported)
{
    FailTpmProvider();
    AnswerKeyProperties(Isolation::not_isolated);
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, ksp_key_handle, _).Times(1).WillOnce(Return(status_failure));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey(mpss::IsolationLevel::mixed);

    EXPECT_EQ(nullptr, key);
    EXPECT_THAT(mpss::get_error(), HasSubstr("cleanup"));
}

// Scenario: the TPM is unavailable, the VBS creation call succeeds, and the created key reports that
// it is isolated.
// Expected behavior: the key is reported as VBS.
TEST_F(WindowsKeyCreation, VbsCreationThatIsIsolatedIsReportedAsVbs)
{
    FailTpmProvider();
    AnswerKeyProperties(Isolation::isolated);

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ("Virtualization Based Security", std::string(key->key_info().storage_description));
    EXPECT_EQ(mpss::IsolationLevel::mixed, key->key_info().isolation_level);
}

// Scenario: the TPM is unavailable, the VBS creation call succeeds, but the isolation property of
// the new key cannot be read.
// Expected behavior: the key is deleted and creation fails, rather than reporting an unverified
// tier.
TEST_F(WindowsKeyCreation, VbsCreationWithUnreadableIsolationDeletesTheKeyAndFails)
{
    FailTpmProvider();
    AnswerKeyProperties(Isolation::read_fails);
    EXPECT_MODULE_FUNC_CALL(NCryptDeleteKey, ksp_key_handle, _).Times(1).WillOnce(Return(ERROR_SUCCESS));

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: a provider cannot say whether it holds the key, because opening the key failed for a
// reason other than the key being absent.
// Expected behavior: the open reports the failure rather than reporting the key as absent. Absence
// and "could not tell" are different answers, and only one of them makes a name safe to create over.
TEST_F(WindowsKeyCreation, OpenReportsFailureWhenAProviderCouldNotBeRead)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _).Times(AnyNumber()).WillRepeatedly(Return(status_failure));

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: every provider reports that it does not hold the key.
// Expected behavior: the open reports a clean negative -- no key and no error -- so the caller can
// tell a name that is free from one that could not be checked.
TEST_F(WindowsKeyCreation, OpenOfAnAbsentKeyReportsNoError)
{
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _).Times(AnyNumber()).WillRepeatedly(Return(status_not_found));

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_FALSE(mpss::has_error());
}

// Scenario: the platform provider cannot be opened at all, and the software KSP reports that it does
// not hold the key. This is what a machine with no usable TPM looks like.
// Expected behavior: a clean negative. One rung failing to open does not make the whole lookup an
// operational failure when the remaining rung answered.
TEST_F(WindowsKeyCreation, OpenOfAnAbsentKeyWithNoTpmStillReportsNoError)
{
    FailTpmProvider();
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _).Times(AnyNumber()).WillRepeatedly(Return(status_not_found));

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_FALSE(mpss::has_error());
}

// Scenario: creation is asked for a name whose store could not be read. Creation itself would
// succeed if it were attempted.
// Expected behavior: creation refuses without attempting to create. The name was never established
// to be free, so writing a key there could overwrite one that already exists.
TEST_F(WindowsKeyCreation, CreateRefusesWhenTheExistenceProbeCouldNotReadTheStore)
{
    int create_attempts = 0;
    EXPECT_MODULE_FUNC_CALL(NCryptOpenKey, _, _, _, _, _).Times(AnyNumber()).WillRepeatedly(Return(status_failure));
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly([&create_attempts](NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *out, LPCWSTR, LPCWSTR, DWORD,
                                           DWORD) -> SECURITY_STATUS {
            ++create_attempts;
            *out = ksp_key_handle;
            return ERROR_SUCCESS;
        });

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_EQ(0, create_attempts);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: the name is held by a key this backend cannot classify, such as an RSA key put there by
// other software.
// Expected behavior: the open reports a failure and creation refuses. The name is taken, even though
// the key that holds it is unusable here.
TEST_F(WindowsKeyCreation, AKeyWithAnUnsupportedAlgorithmIsNotReportedAsAbsent)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, 0, NCRYPT_RSA_ALGORITHM);

    std::unique_ptr<mpss::KeyPair> opened = OpenOsKey();
    EXPECT_EQ(nullptr, opened);
    EXPECT_TRUE(mpss::has_error());
    EXPECT_NE(std::string::npos, mpss::get_error().find("RSA"));

    std::unique_ptr<mpss::KeyPair> created = CreateOsKey();
    EXPECT_EQ(nullptr, created);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: the name is held by an ECDH key agreement key.
// Expected behavior: the open is refused. The algorithm decides what a key may be used for, and a
// key agreement key cannot stand in for a signing key.
TEST_F(WindowsKeyCreation, AnEcdhKeyIsRefused)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, 0, NCRYPT_ECDH_P256_ALGORITHM);

    std::unique_ptr<mpss::KeyPair> opened = OpenOsKey();

    EXPECT_EQ(nullptr, opened);
    EXPECT_TRUE(mpss::has_error());
    EXPECT_NE(std::string::npos, mpss::get_error().find("ECDH_P256"));
}

// Scenario: the key was created through the generic ECDSA identifier, which carries the named group
// in a separate property instead of in the algorithm name.
// Expected behavior: the group resolves the algorithm and the open succeeds. This is an ordinary
// signing key and must keep working.
TEST_F(WindowsKeyCreation, AGenericEcdsaKeyIsResolvedByItsNamedGroup)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, 0, BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECC_CURVE_NISTP256);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::Algorithm::ecdsa_secp256r1_sha256, key->algorithm());
}

TEST_F(WindowsKeyCreation, AGenericEcdsaKeyOnP384IsResolvedByItsNamedGroup)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, 0, BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECC_CURVE_NISTP384);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    ASSERT_NE(nullptr, key);
    EXPECT_EQ(mpss::Algorithm::ecdsa_secp384r1_sha384, key->algorithm());
}

// Scenario: a generic ECDSA key that carries no readable named group, which is what a key created
// from explicit group parameters looks like.
// Expected behavior: refused. The algorithm is a signature algorithm, but which one it is cannot be
// established, and the key size must not be used to fill that gap.
TEST_F(WindowsKeyCreation, AGenericEcdsaKeyWhoseNamedGroupCannotBeReadIsRefused)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, 0, BCRYPT_ECDSA_ALGORITHM);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
    EXPECT_NE(std::string::npos, mpss::get_error().find("named group could not be read"));
}

// Scenario: a generic ECDSA key whose named group this backend does not support.
// Expected behavior: refused, and the error names the group.
TEST_F(WindowsKeyCreation, AGenericEcdsaKeyOnAnUnsupportedGroupIsRefused)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, 0, BCRYPT_ECDSA_ALGORITHM, L"brainpoolP256r1");

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
    EXPECT_NE(std::string::npos, mpss::get_error().find("brainpoolP256r1"));
}

// Scenario: the name is held by a key that permits its private key to be exported, which is not
// something this backend creates.
// Expected behavior: the open is refused. A key whose private material can be taken elsewhere cannot
// offer the protection the caller asked for.
TEST_F(WindowsKeyCreation, AnExportableKeyIsRefusedOnOpen)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, NCRYPT_ALLOW_EXPORT_FLAG);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
    EXPECT_THAT(mpss::get_error(), HasSubstr("export"));
}

// Scenario: the same, for a key that permits export of the private key in the clear.
// Expected behavior: refused for the same reason.
TEST_F(WindowsKeyCreation, APlaintextExportableKeyIsRefusedOnOpen)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::isolated, ERROR_SUCCESS, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: the name is held by a key whose policy allows its private key to be archived, which
// permits export once.
// Expected behavior: refused. One export is enough to put the private material somewhere else.
TEST_F(WindowsKeyCreation, AnArchivableKeyIsRefusedOnOpen)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::isolated, ERROR_SUCCESS, NCRYPT_ALLOW_ARCHIVING_FLAG);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: the same, for a policy that allows the private key to be archived in the clear.
// Expected behavior: refused for the same reason.
TEST_F(WindowsKeyCreation, APlaintextArchivableKeyIsRefusedOnOpen)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::isolated, ERROR_SUCCESS, NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: the export policy of an opened key cannot be read.
// Expected behavior: the open fails rather than using a key whose protection could not be
// established.
TEST_F(WindowsKeyCreation, AKeyWhoseExportPolicyCannotBeReadIsRefused)
{
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::isolated, status_failure, 0);

    std::unique_ptr<mpss::KeyPair> key = OpenOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: creation is asked for a name already held by an exportable key.
// Expected behavior: creation refuses. The name is taken, and the probe must not read a key it
// rejected as a free name.
TEST_F(WindowsKeyCreation, CreateRefusesWhenTheNameIsHeldByAnExportableKey)
{
    int create_attempts = 0;
    KeyLivesIn(ksp_provider_handle);
    AnswerKeyProperties(Isolation::not_isolated, ERROR_SUCCESS, NCRYPT_ALLOW_EXPORT_FLAG);
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly([&create_attempts](NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *out, LPCWSTR, LPCWSTR, DWORD,
                                           DWORD) -> SECURITY_STATUS {
            ++create_attempts;
            *out = ksp_key_handle;
            return ERROR_SUCCESS;
        });

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_EQ(0, create_attempts);
    EXPECT_TRUE(mpss::has_error());
}

// Scenario: the name is free when the existence check runs, and the TPM provider reports it taken
// when the create itself lands -- the window the check cannot close.
// Expected behavior: creation refuses instead of moving to the next provider. The providers keep
// separate namespaces, so creating there would leave two of them holding the name, and a later open
// resolves to whichever the search reaches first -- not necessarily the key this call made.
TEST_F(WindowsKeyCreation, ANameTakenInOneProviderIsNotCreatedInAnother)
{
    int create_attempts = 0;
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly([&create_attempts](NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *out, LPCWSTR, LPCWSTR, DWORD,
                                           DWORD) -> SECURITY_STATUS {
            ++create_attempts;
            if (tpm_provider_handle == provider)
            {
                return status_exists;
            }
            *out = ksp_key_handle;
            return ERROR_SUCCESS;
        });

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_EQ(1, create_attempts) << "a name collision was retried in another provider";
    EXPECT_THAT(mpss::get_error(), HasSubstr("already exists"));
}

// Scenario: no TPM, and the name is taken in the shared provider when the VBS-flagged create lands.
// Expected behavior: creation refuses. VBS and software are the same provider, so the name is taken
// for both of them, and the unflagged retry would address the very key that reported the collision.
TEST_F(WindowsKeyCreation, ANameTakenWithTheVbsFlagIsNotRetriedWithoutIt)
{
    FailTpmProvider();

    int create_attempts = 0;
    EXPECT_MODULE_FUNC_CALL(NCryptCreatePersistedKey, _, _, _, _, _, _)
        .Times(AnyNumber())
        .WillRepeatedly([&create_attempts](NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *, LPCWSTR, LPCWSTR, DWORD,
                                           DWORD) -> SECURITY_STATUS {
            ++create_attempts;
            return status_exists;
        });

    std::unique_ptr<mpss::KeyPair> key = CreateOsKey();

    EXPECT_EQ(nullptr, key);
    EXPECT_EQ(1, create_attempts) << "a name collision was retried in the same provider";
    EXPECT_THAT(mpss::get_error(), HasSubstr("already exists"));
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
