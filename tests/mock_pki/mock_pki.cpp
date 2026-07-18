// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tests/mock_pki/mock_pki.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <functional>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <random>
#include <sstream>

namespace mpss::tests::mock_pki
{

namespace
{

constexpr std::string_view windows_prefix = "MPSS_WINDOWS_TPM_ATTESTATION_V1";
constexpr std::string_view windows_vbs_prefix = "MPSS_WINDOWS_VBS_ATTESTATION_V1";
constexpr std::string_view apple_prefix = "MPSS_APP_ATTEST_V1";
constexpr std::string_view apple_acme_prefix = "MPSS_APPLE_ACME_MDA_V1";

constexpr std::string_view to_string(AttestationFormat format)
{
    switch (format)
    {
    case AttestationFormat::none:
        return "none";
    case AttestationFormat::windows_vbs:
        return "windows_vbs";
    case AttestationFormat::windows_tpm:
        return "windows_tpm";
    case AttestationFormat::android_key_attestation:
        return "android_key_attestation";
    case AttestationFormat::apple_app_attest:
        return "apple_app_attest";
    case AttestationFormat::apple_acme_managed_device_attestation:
        return "apple_acme_managed_device_attestation";
    default:
        return "unknown";
    }
}

constexpr std::string_view to_string(RejectReason reason)
{
    switch (reason)
    {
    case RejectReason::missing_evidence:
        return "missing_evidence";
    case RejectReason::wrong_format:
        return "wrong_format";
    case RejectReason::invalid_structure:
        return "invalid_structure";
    case RejectReason::nonce_not_found:
        return "nonce_not_found";
    case RejectReason::nonce_expired:
        return "nonce_expired";
    case RejectReason::nonce_replayed:
        return "nonce_replayed";
    case RejectReason::nonce_mismatch:
        return "nonce_mismatch";
    case RejectReason::public_key_mismatch:
        return "public_key_mismatch";
    default:
        return "unknown";
    }
}

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using EVPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;
struct X509StackDeleter
{
    void operator()(STACK_OF(X509) *stack) const
    {
        if (nullptr != stack)
        {
            sk_X509_pop_free(stack, X509_free);
        }
    }
};
using X509StackPtr = std::unique_ptr<STACK_OF(X509), X509StackDeleter>;

X509Ptr parse_der_cert(std::span<const std::byte> der)
{
    const auto *begin = reinterpret_cast<const unsigned char *>(der.data());
    const auto *cursor = begin;
    X509 *cert = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
    if (nullptr == cert || cursor != begin + static_cast<std::ptrdiff_t>(der.size()))
    {
        if (nullptr != cert)
        {
            X509_free(cert);
        }
        return X509Ptr(nullptr, X509_free);
    }
    return X509Ptr(cert, X509_free);
}

bool serialize_pubkey_der(EVP_PKEY *key, std::vector<std::byte> &out)
{
    if (nullptr == key)
    {
        return false;
    }

    const int size = i2d_PUBKEY(key, nullptr);
    if (size <= 0)
    {
        return false;
    }

    out.resize(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(out.data());
    const int written = i2d_PUBKEY(key, &cursor);
    return written == size;
}

bool cert_der_equal(const std::vector<std::byte> &lhs, const std::vector<std::byte> &rhs)
{
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

// Minimal DER length-field reader. Returns the decoded length and advances `offset`.
// Returns -1 if the encoding is invalid or truncated.
// Supports short form (1 byte) and long form (up to 3 additional bytes).
int read_asn1_length(const unsigned char *buf, int buf_end, int &offset)
{
    if (offset >= buf_end)
    {
        return -1;
    }
    const unsigned char len_byte = buf[offset++];
    if (0 == (len_byte & 0x80U))
    {
        return static_cast<int>(len_byte);
    }
    const int num_bytes = static_cast<int>(len_byte & 0x7FU);
    if (num_bytes == 0 || num_bytes > 3 || offset + num_bytes > buf_end)
    {
        return -1;
    }
    int length = 0;
    for (int i = 0; i < num_bytes; ++i)
    {
        length = (length << 8) | static_cast<int>(buf[offset++]);
    }
    return length;
}

// Extract the attestationChallenge OCTET STRING from the Android Key Attestation
// extension value (OID 1.3.6.1.4.1.11129.2.1.17).
//
// The extension value is the DER encoding of:
//   KeyDescription ::= SEQUENCE {
//     attestationVersion         INTEGER,        -- field 0 (skipped)
//     attestationSecurityLevel   ENUMERATED,     -- field 1 (skipped)
//     keymasterVersion           INTEGER,        -- field 2 (skipped)
//     keymasterSecurityLevel     ENUMERATED,     -- field 3 (skipped)
//     attestationChallenge       OCTET STRING,   -- field 4 (extracted)
//     ...
//   }
//
// Returns true and fills `challenge` on success. Returns false if the
// structure is missing, truncated, or field 4 is not an OCTET STRING.
bool parse_android_attestation_challenge(const unsigned char *der, int der_len,
                                         std::vector<std::byte> &challenge)
{
    if (nullptr == der || der_len < 2)
    {
        return false;
    }

    int offset = 0;

    // Outer SEQUENCE tag (0x30).
    if (der[offset++] != 0x30)
    {
        return false;
    }
    const int seq_len = read_asn1_length(der, der_len, offset);
    if (seq_len < 0 || offset + seq_len > der_len)
    {
        return false;
    }
    const int seq_end = offset + seq_len;

    // Skip fields 0–3 (attestationVersion, attestationSecurityLevel,
    // keymasterVersion, keymasterSecurityLevel).
    for (int field = 0; field < 4; ++field)
    {
        if (offset + 1 > seq_end)
        {
            return false; // truncated
        }
        ++offset; // skip tag byte
        const int field_len = read_asn1_length(der, seq_end, offset);
        if (field_len < 0 || offset + field_len > seq_end)
        {
            return false;
        }
        offset += field_len;
    }

    // Field 4: attestationChallenge OCTET STRING (DER tag 0x04).
    if (offset + 1 > seq_end || der[offset] != 0x04)
    {
        return false;
    }
    ++offset;
    const int chal_len = read_asn1_length(der, seq_end, offset);
    if (chal_len < 0 || offset + chal_len > seq_end)
    {
        return false;
    }

    challenge.assign(reinterpret_cast<const std::byte *>(der + offset),
                     reinterpret_cast<const std::byte *>(der + offset + chal_len));
    return true;
}

} // namespace

MockPkiService::MockPkiService(std::chrono::seconds ttl) : ttl_{ttl}
{
}

void MockPkiService::set_trusted_root(AttestationFormat format, std::vector<std::byte> der_certificate)
{
    trusted_roots_[format] = std::move(der_certificate);
}

std::vector<std::byte> MockPkiService::issue_challenge()
{
    std::vector<std::byte> nonce(32);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::generate(nonce.begin(), nonce.end(), [&] { return static_cast<std::byte>(dist(gen)); });

    outstanding_[nonce_key(nonce)] = NonceState{std::chrono::steady_clock::now() + ttl_, false};
    return nonce;
}

SubmitResult MockPkiService::submit(const MockCsr &csr, const std::optional<AttestationEvidence> &evidence,
                                    AttestationFormat expected_format)
{
    if (!evidence.has_value())
    {
        mpss::utils::log_warning("Mock PKI rejected CSR: missing attestation evidence.");
        return {false, RejectReason::missing_evidence, false};
    }
    return submit(csr, *evidence, expected_format);
}

SubmitResult MockPkiService::submit(const MockCsr &csr, const AttestationEvidence &evidence,
                                    AttestationFormat expected_format)
{
    const auto reject = [&](RejectReason reason) {
        mpss::utils::log_warning("Mock PKI rejected attestation (expected={}, actual={}): {}.",
                                 to_string(expected_format), to_string(evidence.format), to_string(reason));
        return SubmitResult{false, reason, false};
    };

    if (AttestationFormat::none == evidence.format || expected_format != evidence.format)
    {
        return reject(RejectReason::wrong_format);
    }

    std::vector<std::byte> challenge;
    std::vector<std::byte> attested_public_key;
    if (AttestationFormat::android_key_attestation == evidence.format)
    {
        // Android Key Attestation: the cert chain is the evidence.
        // The server-issued challenge must be present in the leaf certificate's
        // Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
        // The statement field is empty for Android — do not parse it.
        if (evidence.cert_chain.empty())
        {
            return reject(RejectReason::invalid_structure);
        }

        // Parse the leaf certificate (first entry in the chain).
        using X509ObjPtr = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
        X509Ptr leaf = parse_der_cert(evidence.cert_chain.front());
        if (nullptr == leaf)
        {
            return reject(RejectReason::invalid_structure);
        }

        // Locate the Android Key Attestation extension by OID 1.3.6.1.4.1.11129.2.1.17.
        X509ObjPtr android_oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1), ASN1_OBJECT_free);
        if (nullptr == android_oid)
        {
            return reject(RejectReason::invalid_structure);
        }
        const int ext_idx = X509_get_ext_by_OBJ(leaf.get(), android_oid.get(), -1);
        if (ext_idx < 0)
        {
            mpss::utils::log_warning("Mock PKI: Android Key Attestation extension not found in leaf cert.");
            return reject(RejectReason::invalid_structure);
        }
        X509_EXTENSION *ext = X509_get_ext(leaf.get(), ext_idx);
        if (nullptr == ext)
        {
            return reject(RejectReason::invalid_structure);
        }

        // The extension value (extnValue) is an OCTET STRING whose content is
        // the DER encoding of the KeyDescription SEQUENCE defined in the Android
        // Keystore attestation specification. Extract attestationChallenge from it.
        const ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
        if (nullptr == ext_data)
        {
            return reject(RejectReason::invalid_structure);
        }
        const unsigned char *der = ASN1_STRING_get0_data(ext_data);
        const int der_len = ASN1_STRING_length(ext_data);
        if (!parse_android_attestation_challenge(der, der_len, challenge))
        {
            mpss::utils::log_warning("Mock PKI: failed to parse attestationChallenge from Android extension.");
            return reject(RejectReason::invalid_structure);
        }

        // Extract the leaf public key for the key-binding check below.
        EVPKeyPtr leaf_key(X509_get_pubkey(leaf.get()), EVP_PKEY_free);
        if (nullptr == leaf_key || !serialize_pubkey_der(leaf_key.get(), attested_public_key))
        {
            return reject(RejectReason::invalid_structure);
        }

        // Verify the full cert chain chains to the configured trusted root.
        if (!verify_cert_chain(evidence.cert_chain, evidence.format, attested_public_key))
        {
            return reject(RejectReason::invalid_structure);
        }
    }
    else if (AttestationFormat::windows_tpm == evidence.format || AttestationFormat::windows_vbs == evidence.format)
    {
        if (evidence.cert_chain.empty())
        {
            return reject(RejectReason::invalid_structure);
        }
        const std::string_view prefix = (AttestationFormat::windows_vbs == evidence.format) ? windows_vbs_prefix
                                                                                             : windows_prefix;
        const std::span<const char> prefix_chars{prefix.data(), prefix.size()};
        if (!parse_challenge_and_key(evidence.statement, std::as_bytes(prefix_chars), challenge,
                                     attested_public_key))
        {
            return reject(RejectReason::invalid_structure);
        }
        if (!verify_cert_chain(evidence.cert_chain, evidence.format, attested_public_key))
        {
            return reject(RejectReason::invalid_structure);
        }
    }
    else if (AttestationFormat::apple_app_attest == evidence.format)
    {
        if (evidence.statement.size() <= apple_prefix.size())
        {
            return reject(RejectReason::invalid_structure);
        }
        if (!std::equal(apple_prefix.begin(), apple_prefix.end(),
                        reinterpret_cast<const char *>(evidence.statement.data())))
        {
            return reject(RejectReason::invalid_structure);
        }
        challenge.assign(evidence.statement.begin() + static_cast<std::ptrdiff_t>(apple_prefix.size()),
                         evidence.statement.end() - static_cast<std::ptrdiff_t>(sizeof(std::size_t)));
        if (evidence.statement.size() < apple_prefix.size() + sizeof(std::size_t))
        {
            return reject(RejectReason::invalid_structure);
        }

        const std::string csr_key(reinterpret_cast<const char *>(csr.public_key.data()), csr.public_key.size());
        const std::size_t expected_binding = std::hash<std::string>{}(csr_key);
        std::size_t encoded_binding = 0;
        const std::size_t offset = evidence.statement.size() - sizeof(std::size_t);
        for (std::size_t i = 0; i < sizeof(std::size_t); ++i)
        {
            encoded_binding |=
                (static_cast<std::size_t>(std::to_integer<unsigned int>(evidence.statement[offset + i])) & 0xFFU)
                << (i * 8U);
        }
        if (encoded_binding != expected_binding)
        {
            return reject(RejectReason::public_key_mismatch);
        }
        attested_public_key = csr.public_key;
    }
    else if (AttestationFormat::apple_acme_managed_device_attestation == evidence.format)
    {
        if (evidence.cert_chain.empty())
        {
            return reject(RejectReason::invalid_structure);
        }
        const std::span<const char> prefix_chars{apple_acme_prefix.data(), apple_acme_prefix.size()};
        if (!parse_challenge_and_key(evidence.statement, std::as_bytes(prefix_chars), challenge, attested_public_key))
        {
            return reject(RejectReason::invalid_structure);
        }
        if (!verify_cert_chain(evidence.cert_chain, evidence.format, attested_public_key))
        {
            return reject(RejectReason::invalid_structure);
        }
    }

    const auto nonce_it = outstanding_.find(nonce_key(challenge));
    if (outstanding_.end() == nonce_it)
    {
        return reject(RejectReason::nonce_not_found);
    }
    if (nonce_it->second.used)
    {
        return reject(RejectReason::nonce_replayed);
    }
    if (std::chrono::steady_clock::now() > nonce_it->second.expires_at)
    {
        return reject(RejectReason::nonce_expired);
    }
    if (attested_public_key != csr.public_key)
    {
        return reject(RejectReason::public_key_mismatch);
    }

    nonce_it->second.used = true;
    const bool weaker_assurance = AttestationFormat::apple_app_attest == evidence.format;
    mpss::utils::log_info("Mock PKI accepted attestation (format={}, weaker_assurance={}).", to_string(evidence.format),
                          weaker_assurance ? "true" : "false");
    return {true, std::nullopt, weaker_assurance};
}

std::string MockPkiService::nonce_key(std::span<const std::byte> nonce)
{
    std::ostringstream out;
    for (const std::byte b : nonce)
    {
        out << std::hex << std::to_integer<unsigned int>(b);
    }
    return out.str();
}

bool MockPkiService::verify_cert_chain(std::span<const std::vector<std::byte>> cert_chain, AttestationFormat format,
                                       std::span<const std::byte> expected_leaf_public_key) const
{
    const auto root_it = trusted_roots_.find(format);
    if (trusted_roots_.end() == root_it || cert_chain.empty())
    {
        return false;
    }

    X509Ptr trusted_root = parse_der_cert(root_it->second);
    X509Ptr leaf = parse_der_cert(cert_chain.front());
    if (nullptr == trusted_root || nullptr == leaf)
    {
        return false;
    }

    EVPKeyPtr leaf_key(X509_get_pubkey(leaf.get()), EVP_PKEY_free);
    std::vector<std::byte> leaf_pubkey_der;
    if (nullptr == leaf_key || !serialize_pubkey_der(leaf_key.get(), leaf_pubkey_der)
        || leaf_pubkey_der.size() != expected_leaf_public_key.size()
        || !std::equal(leaf_pubkey_der.begin(), leaf_pubkey_der.end(), expected_leaf_public_key.begin()))
    {
        return false;
    }

    X509StorePtr store(X509_STORE_new(), X509_STORE_free);
    if (nullptr == store || 1 != X509_STORE_add_cert(store.get(), trusted_root.get()))
    {
        return false;
    }

    X509StackPtr untrusted(sk_X509_new_null());
    if (nullptr == untrusted)
    {
        return false;
    }

    for (std::size_t i = 1; i < cert_chain.size(); ++i)
    {
        if (cert_der_equal(cert_chain[i], root_it->second))
        {
            continue;
        }
        X509Ptr cert = parse_der_cert(cert_chain[i]);
        if (nullptr == cert)
        {
            return false;
        }
        if (1 != sk_X509_push(untrusted.get(), cert.release()))
        {
            return false;
        }
    }

    X509StoreCtxPtr ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (nullptr == ctx || 1 != X509_STORE_CTX_init(ctx.get(), store.get(), leaf.get(), untrusted.get()))
    {
        return false;
    }

    return 1 == X509_verify_cert(ctx.get());
}

bool MockPkiService::parse_challenge_and_key(std::span<const std::byte> statement, std::span<const std::byte> prefix,
                                             std::vector<std::byte> &challenge, std::vector<std::byte> &public_key)
{
    if (statement.size() < prefix.size() + 2)
    {
        return false;
    }
    if (!std::equal(prefix.begin(), prefix.end(), statement.begin()))
    {
        return false;
    }

    std::size_t offset = prefix.size();
    const std::size_t challenge_size = std::to_integer<std::size_t>(statement[offset]);
    ++offset;
    if (statement.size() < offset + challenge_size + 1)
    {
        return false;
    }
    challenge.assign(statement.begin() + static_cast<std::ptrdiff_t>(offset),
                     statement.begin() + static_cast<std::ptrdiff_t>(offset + challenge_size));
    offset += challenge_size;

    const std::size_t pk_size = std::to_integer<std::size_t>(statement[offset]);
    ++offset;
    if (statement.size() < offset + pk_size)
    {
        return false;
    }
    public_key.assign(statement.begin() + static_cast<std::ptrdiff_t>(offset),
                      statement.begin() + static_cast<std::ptrdiff_t>(offset + pk_size));
    return true;
}

} // namespace mpss::tests::mock_pki
