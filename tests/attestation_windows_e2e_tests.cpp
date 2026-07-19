// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Windows-only, real-hardware attestation E2E tests (empty TU on other platforms). The VBS
// create -> claim -> verify round trip is the one real-attestation E2E that runs on hosted CI (VBS is
// present on the hosted windows-2022 runner even with no TPM); the backend attested-Create path
// exercises the shipping code end to end. Both are gated on real evidence being producible, so hosted
// CI stays green without ever faking evidence.

#if defined(_WIN32)

#include "mpss-attest-verify/attestation_verifier.h"
#include "mpss/attestation.h"
#include "mpss/mpss.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

// clang-format off
#include <Windows.h>
#include <ncrypt.h>
// clang-format on

namespace mpss::tests
{

namespace
{

// VBS_ROOT (0x5) on Win11 SDKs; the legacy statement type (0x4) auto-transforms to it and is
// available on older SDKs. Mirrors the resolution used by the Windows backend.
#if defined(NCRYPT_CLAIM_VBS_ROOT)
constexpr DWORD kVbsClaimType = NCRYPT_CLAIM_VBS_ROOT;
#else
constexpr DWORD kVbsClaimType = NCRYPT_CLAIM_VBS_KEY_ATTESTATION_STATEMENT;
#endif

std::vector<std::byte> make_nonce()
{
    // Deterministic, non-trivial nonce; content is irrelevant to the crypto, only that it round-trips.
    std::vector<std::byte> nonce(32);
    for (std::size_t i = 0; i < nonce.size(); ++i)
    {
        nonce[i] = static_cast<std::byte>(0x40U + i);
    }
    return nonce;
}

// RAII for an NCRYPT handle (provider or key), freed with NCryptFreeObject.
struct NcryptHandle
{
    NCRYPT_HANDLE h{0};
    ~NcryptHandle()
    {
        if (h != 0)
        {
            ::NCryptFreeObject(h);
        }
    }
};

} // namespace

// Scenario: full VBS / Key Guard create -> claim -> verify round trip against the live CNG API.
// Expected behavior: on a VBS-capable runner (incl. hosted windows-latest with no TPM) the claim
// verifies (NCryptVerifyClaim == ERROR_SUCCESS), a tampered claim is rejected, and the shared
// cross-platform verifier still refuses the format as not externally verifiable.
TEST(WindowsVbsE2ETest, GenerateVerifyRoundTrip)
{
    NCRYPT_PROV_HANDLE raw_provider = 0;
    ASSERT_EQ(::NCryptOpenStorageProvider(&raw_provider, MS_KEY_STORAGE_PROVIDER, 0), ERROR_SUCCESS);
    NcryptHandle provider{raw_provider};

    const wchar_t *key_name = L"mpss_vbs_e2e_test_key";

    // Clean up any key left behind by a previous interrupted run.
    {
        NCRYPT_KEY_HANDLE stale = 0;
        if (::NCryptOpenKey(raw_provider, &stale, key_name, 0, 0) == ERROR_SUCCESS)
        {
            ::NCryptDeleteKey(stale, 0);
        }
    }

    NCRYPT_KEY_HANDLE raw_key = 0;
    SECURITY_STATUS status = ::NCryptCreatePersistedKey(raw_provider, &raw_key, BCRYPT_ECDSA_P256_ALGORITHM, key_name,
                                                        0, NCRYPT_USE_VIRTUAL_ISOLATION_FLAG);
    if (status != ERROR_SUCCESS)
    {
        GTEST_SKIP() << "VBS key creation not available on this runner (status 0x" << std::hex << status << ").";
    }
    NcryptHandle key{raw_key};

    status = ::NCryptFinalizeKey(raw_key, 0);
    if (status != ERROR_SUCCESS)
    {
        ::NCryptDeleteKey(raw_key, 0);
        key.h = 0;
        GTEST_SKIP() << "VBS key finalize failed (status 0x" << std::hex << status << ").";
    }

    std::vector<std::byte> nonce = make_nonce();
    BCryptBuffer nonce_buffer{};
    nonce_buffer.cbBuffer = static_cast<ULONG>(nonce.size());
    nonce_buffer.BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE;
    nonce_buffer.pvBuffer = nonce.data();
    BCryptBufferDesc parameter_list{};
    parameter_list.ulVersion = BCRYPTBUFFER_VERSION;
    parameter_list.cBuffers = 1;
    parameter_list.pBuffers = &nonce_buffer;

    DWORD claim_size = 0;
    ASSERT_EQ(::NCryptCreateClaim(raw_key, 0, kVbsClaimType, &parameter_list, nullptr, 0, &claim_size, 0),
              ERROR_SUCCESS);
    ASSERT_GT(claim_size, 0U);
    std::vector<std::byte> claim(claim_size);
    ASSERT_EQ(::NCryptCreateClaim(raw_key, 0, kVbsClaimType, &parameter_list, reinterpret_cast<PBYTE>(claim.data()),
                                  claim_size, &claim_size, 0),
              ERROR_SUCCESS);
    claim.resize(claim_size);

    // Export the public key and re-import it as a public key handle to verify against.
    DWORD pub_size = 0;
    ASSERT_EQ(::NCryptExportKey(raw_key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &pub_size, 0), ERROR_SUCCESS);
    std::vector<std::byte> pub(pub_size);
    ASSERT_EQ(::NCryptExportKey(raw_key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, reinterpret_cast<PBYTE>(pub.data()),
                                pub_size, &pub_size, 0),
              ERROR_SUCCESS);

    NCRYPT_KEY_HANDLE raw_imported = 0;
    ASSERT_EQ(::NCryptImportKey(raw_provider, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, &raw_imported,
                                reinterpret_cast<PBYTE>(pub.data()), pub_size, 0),
              ERROR_SUCCESS);
    NcryptHandle imported{raw_imported};

    // Minimal-correct NCryptVerifyClaim usage: hAuthorityKey=NULL, pParameterList=NULL (the nonce
    // lives inside the claim), a non-NULL output descriptor, and no details flag -> ERROR_SUCCESS
    // with cBuffers==0 (nothing to free). Passing the nonce here instead yields NTE_INVALID_PARAMETER.
    NCryptBufferDesc output{};
    output.ulVersion = BCRYPTBUFFER_VERSION;
    const SECURITY_STATUS verify_status =
        ::NCryptVerifyClaim(raw_imported, 0, kVbsClaimType, nullptr, reinterpret_cast<PBYTE>(claim.data()),
                            static_cast<DWORD>(claim.size()), &output, 0);
    EXPECT_EQ(verify_status, ERROR_SUCCESS) << "NCryptVerifyClaim failed (0x" << std::hex << verify_status << ").";

    std::vector<std::byte> tampered = claim;
    tampered.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(tampered.back()) ^ 0xFFU);
    NCryptBufferDesc tampered_output{};
    tampered_output.ulVersion = BCRYPTBUFFER_VERSION;
    const SECURITY_STATUS tampered_status =
        ::NCryptVerifyClaim(raw_imported, 0, kVbsClaimType, nullptr, reinterpret_cast<PBYTE>(tampered.data()),
                            static_cast<DWORD>(tampered.size()), &tampered_output, 0);
    EXPECT_NE(tampered_status, ERROR_SUCCESS) << "Tampered VBS claim unexpectedly verified.";

    // The shared cross-platform verifier must still refuse the VBS format: it is not externally
    // verifiable regardless of the on-device self-verification succeeding.
    mpss::AttestationEvidence evidence;
    evidence.format = mpss::AttestationFormat::windows_vbs_claim;
    evidence.payload = claim;
    const mpss::attest::AttestationVerifier cross_platform;
    const auto cross_result = cross_platform.verify(evidence, nonce, pub);
    EXPECT_FALSE(cross_result.ok);
    EXPECT_EQ(cross_result.format, mpss::AttestationFormat::windows_vbs_claim);
    EXPECT_NE(cross_result.reason.find("not externally verifiable"), std::string::npos);

    ::NCryptDeleteKey(raw_key, 0);
    key.h = 0;
}

// Scenario: the shipping mpss backend creates a key with a required attestation request.
// Expected behavior: real nonce-bound evidence is attached (windows_tpm_claim when a TPM is present,
// otherwise windows_vbs_claim), the key is a usable signing key, and the shared verifier handles the
// evidence per format (TPM -> reaches the documented chain gap; VBS -> refused). Gated on the backend
// being able to attest at all so a runner with neither TPM nor VBS stays green.
TEST(WindowsAttestedCreateE2ETest, BackendProducesRealEvidence)
{
    const std::vector<std::byte> nonce = make_nonce();
    mpss::AttestationRequest request;
    request.challenge = nonce;
    request.requirement = mpss::AttestationRequirement::require;

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(
        "mpss_attested_e2e_key", mpss::Algorithm::ecdsa_secp256r1_sha256, mpss::KeyPolicy::none, request);
    if (key == nullptr)
    {
        GTEST_SKIP() << "No TPM or VBS attestation available on this runner: " << mpss::get_error();
    }

    // Capture everything we need, then delete the key, so later ASSERT failures never leak storage.
    const bool supports = key->supports_attestation();
    const std::optional<mpss::AttestationEvidence> evidence = key->attestation();

    std::vector<std::byte> pubkey(key->extract_key_size());
    const std::size_t pub_written = key->extract_key(pubkey);
    if (pub_written != 0)
    {
        pubkey.resize(pub_written);
    }

    // The attested key must be a normal, usable signing key.
    const std::vector<std::byte> hash(32, std::byte{0x5A});
    std::vector<std::byte> sig(key->sign_hash_size());
    const std::size_t sig_written = key->sign_hash(hash, sig);
    if (sig_written != 0)
    {
        sig.resize(sig_written);
        EXPECT_TRUE(key->verify(hash, sig));
    }
    else
    {
        ADD_FAILURE() << "attested key could not sign";
    }

    EXPECT_TRUE(key->delete_key());

    EXPECT_TRUE(supports);
    ASSERT_TRUE(evidence.has_value());
    ASSERT_TRUE(std::holds_alternative<mpss::NCryptClaim>(evidence->payload));
    EXPECT_FALSE(std::get<mpss::NCryptClaim>(evidence->payload).empty());
    EXPECT_FALSE(pubkey.empty());
    EXPECT_TRUE(evidence->format == mpss::AttestationFormat::windows_tpm_claim ||
                evidence->format == mpss::AttestationFormat::windows_vbs_claim);

    // Feed the real evidence into the shared verifier with a pinned (placeholder) TPM root.
    mpss::attest::AttestationVerifier::Policy policy;
    policy.roots = [](mpss::AttestationFormat format) {
        std::vector<mpss::attest::TrustAnchor> anchors;
        if (format == mpss::AttestationFormat::windows_tpm_claim)
        {
            anchors.push_back(mpss::attest::TrustAnchor{std::vector<std::byte>(64, std::byte{0xC0})});
        }
        return anchors;
    };
    const mpss::attest::AttestationVerifier verifier{std::move(policy)};
    const auto result = verifier.verify(*evidence, nonce, pubkey);

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.format, evidence->format);
    if (evidence->format == mpss::AttestationFormat::windows_tpm_claim)
    {
        // A real TPM claim parses cleanly and is nonce-bound, so it reaches the documented
        // AIK -> EK -> manufacturer-root chain gap rather than any earlier structural rejection.
        EXPECT_NE(result.reason.find("manufacturer-root"), std::string::npos) << "reason: " << result.reason;
    }
    else
    {
        EXPECT_NE(result.reason.find("not externally verifiable"), std::string::npos) << "reason: " << result.reason;
    }
}

} // namespace mpss::tests

#endif // defined(_WIN32)
