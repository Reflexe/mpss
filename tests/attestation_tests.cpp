// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/algorithm.h"
#include "mpss/attestation.h"
#include "mpss/mpss.h"
#include "tests/mock_pki/mock_pki.h"
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <functional>

namespace mpss::tests
{

namespace
{

std::vector<std::byte> BuildStatement(std::string_view prefix, std::span<const std::byte> challenge,
                                      std::span<const std::byte> public_key)
{
    std::vector<std::byte> statement;
    statement.reserve(prefix.size() + challenge.size() + public_key.size() + 2);
    for (char c : prefix)
    {
        statement.push_back(static_cast<std::byte>(c));
    }
    statement.push_back(static_cast<std::byte>(challenge.size() & 0xFFU));
    statement.insert(statement.end(), challenge.begin(), challenge.end());
    statement.push_back(static_cast<std::byte>(public_key.size() & 0xFFU));
    statement.insert(statement.end(), public_key.begin(), public_key.end());
    return statement;
}

std::vector<std::byte> BuildAppleAppAttestStatement(std::span<const std::byte> challenge,
                                                    std::span<const std::byte> public_key)
{
    static constexpr std::string_view prefix = "MPSS_APP_ATTEST_V1";
    std::vector<std::byte> statement;
    statement.reserve(prefix.size() + challenge.size() + sizeof(std::size_t));
    for (char c : prefix)
    {
        statement.push_back(static_cast<std::byte>(c));
    }
    statement.insert(statement.end(), challenge.begin(), challenge.end());

    const std::string key_material(reinterpret_cast<const char *>(public_key.data()), public_key.size());
    const std::size_t binding = std::hash<std::string>{}(key_material);
    for (std::size_t i = 0; i < sizeof(binding); ++i)
    {
        statement.push_back(static_cast<std::byte>((binding >> (i * 8U)) & 0xFFU));
    }
    return statement;
}

} // namespace

TEST(AttestationApiTest, EmptyChallengeFailsCreate)
{
    if (!mpss::is_algorithm_available(Algorithm::ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const AttestationRequest req{};
    auto key = KeyPair::Create("attestation_empty_challenge", Algorithm::ecdsa_secp256r1_sha256, req);
    EXPECT_EQ(nullptr, key);
    if (nullptr != key)
    {
        key->delete_key();
    }
}

TEST(MockPkiTest, AcceptsAndroidEvidence)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const std::vector<std::byte> public_key{std::byte{0x04}, std::byte{0x01}, std::byte{0x02}};

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::android_key_attestation;
    evidence.statement = BuildStatement("MPSS_ANDROID_KEY_ATTESTATION_V1", challenge, public_key);
    evidence.cert_chain.push_back({std::byte{0x30}, std::byte{0x82}});

    const auto result =
        pki.submit(mock_pki::MockCsr{public_key}, evidence, AttestationFormat::android_key_attestation);
    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
}

TEST(MockPkiTest, RejectsNonceReplay)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const std::vector<std::byte> public_key{std::byte{0x04}, std::byte{0x0A}, std::byte{0x0B}};

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::windows_tpm;
    evidence.statement = BuildStatement("MPSS_WINDOWS_TPM_ATTESTATION_V1", challenge, public_key);

    const auto first = pki.submit(mock_pki::MockCsr{public_key}, evidence, AttestationFormat::windows_tpm);
    const auto second = pki.submit(mock_pki::MockCsr{public_key}, evidence, AttestationFormat::windows_tpm);

    EXPECT_TRUE(first.signed_cert);
    ASSERT_TRUE(second.reject_reason.has_value());
    EXPECT_EQ(mock_pki::RejectReason::nonce_replayed, *second.reject_reason);
}

TEST(MockPkiTest, RejectsPublicKeyMismatch)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const std::vector<std::byte> evidence_key{std::byte{0x04}, std::byte{0x03}, std::byte{0x04}};
    const std::vector<std::byte> csr_key{std::byte{0x04}, std::byte{0xAA}, std::byte{0xBB}};

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::windows_tpm;
    evidence.statement = BuildStatement("MPSS_WINDOWS_TPM_ATTESTATION_V1", challenge, evidence_key);

    const auto result = pki.submit(mock_pki::MockCsr{csr_key}, evidence, AttestationFormat::windows_tpm);
    ASSERT_TRUE(result.reject_reason.has_value());
    EXPECT_EQ(mock_pki::RejectReason::public_key_mismatch, *result.reject_reason);
}

TEST(MockPkiTest, AppleAppAttestIsMarkedAsWeakerAssurance)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const std::vector<std::byte> public_key{std::byte{0x04}, std::byte{0x10}, std::byte{0x11}};

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::apple_app_attest;
    evidence.statement = BuildAppleAppAttestStatement(challenge, public_key);

    const auto result = pki.submit(mock_pki::MockCsr{public_key}, evidence, AttestationFormat::apple_app_attest);
    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
    EXPECT_TRUE(result.weaker_assurance);
}

TEST(MockPkiTest, AcceptsAppleAcmeManagedDeviceEvidence)
{
    mock_pki::MockPkiService pki;
    const auto challenge = pki.issue_challenge();
    const std::vector<std::byte> public_key{std::byte{0x04}, std::byte{0x21}, std::byte{0x22}};

    AttestationEvidence evidence{};
    evidence.format = AttestationFormat::apple_acme_managed_device_attestation;
    evidence.statement = BuildStatement("MPSS_APPLE_ACME_MDA_V1", challenge, public_key);
    evidence.cert_chain.push_back({std::byte{0x30}, std::byte{0x83}});

    const auto result = pki.submit(mock_pki::MockCsr{public_key}, evidence,
                                   AttestationFormat::apple_acme_managed_device_attestation);
    EXPECT_TRUE(result.signed_cert);
    EXPECT_FALSE(result.reject_reason.has_value());
    EXPECT_FALSE(result.weaker_assurance);
}

} // namespace mpss::tests
