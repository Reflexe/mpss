// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/android_key_attestation.h"
#include "mpss/attestation.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace mpss::attest
{

namespace
{

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;
using Asn1ObjectPtr = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509StackPtr = std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509) *)>;

// https://source.android.com/docs/security/features/keystore/attestation
constexpr const char *attestation_extension_oid = "1.3.6.1.4.1.11129.2.1.17";

// Google's software attestation root, embedded only so it can be rejected as an anchor (it carries
// no hardware guarantee). Source: android/keyattestation SoftwareRoot.kt.
constexpr const char *google_software_root_pem = R"(-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
-----END CERTIFICATE-----)";

// The two published Google hardware attestation roots (legacy RSA + RKP EC): the only externally
// verifiable anchors for this format. Source: android/keyattestation roots.json.
constexpr const char *google_hardware_root_rsa_pem = R"(-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----)";

constexpr const char *google_hardware_root_ec_pem = R"(-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----)";

AttestationVerifier::Result reject(std::string reason)
{
    return AttestationVerifier::Result{/* ok */ false, AttestationFormat::android_key_attestation, std::move(reason)};
}

X509Ptr parse_der(const std::vector<std::byte> &der)
{
    const auto *cursor = reinterpret_cast<const unsigned char *>(der.data());
    X509 *cert = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
    return X509Ptr{cert, X509_free};
}

X509Ptr parse_pem(const char *pem)
{
    BioPtr bio{BIO_new_mem_buf(pem, -1), BIO_free};
    if (nullptr == bio)
    {
        return X509Ptr{nullptr, X509_free};
    }
    X509 *cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    return X509Ptr{cert, X509_free};
}

// Canonical DER SubjectPublicKeyInfo of a certificate's public key.
std::vector<std::byte> spki_of(X509 *cert)
{
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    if (nullptr == pkey)
    {
        return {};
    }
    const int size = i2d_PUBKEY(pkey, nullptr);
    if (size <= 0)
    {
        return {};
    }
    std::vector<std::byte> out(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(out.data());
    if (i2d_PUBKEY(pkey, &cursor) != size)
    {
        return {};
    }
    return out;
}

bool bytes_equal(std::span<const std::byte> a, std::span<const std::byte> b)
{
    return a.size() == b.size() && 0 == std::memcmp(a.data(), b.data(), a.size());
}

bool has_attestation_extension(X509 *cert, ASN1_OBJECT *oid)
{
    return X509_get_ext_by_OBJ(cert, oid, -1) >= 0;
}

// A single DER TLV element resolved within [p, end).
struct Tlv
{
    int tag{0};
    int xclass{0};
    const unsigned char *content{nullptr};
    long len{0};
    const unsigned char *next{nullptr};
    bool ok{false};
};

Tlv read_tlv(const unsigned char *p, const unsigned char *end)
{
    Tlv tlv;
    if (nullptr == p || p >= end)
    {
        return tlv;
    }
    const unsigned char *cursor = p;
    long len = 0;
    int tag = 0;
    int xclass = 0;
    const int ret = ASN1_get_object(&cursor, &len, &tag, &xclass, end - p);
    if (0 != (ret & 0x80)) // 0x80 flags a parse error
    {
        return tlv;
    }
    if (len < 0 || cursor + len > end)
    {
        return tlv;
    }
    tlv.tag = tag;
    tlv.xclass = xclass;
    tlv.content = cursor;
    tlv.len = len;
    tlv.next = cursor + len;
    tlv.ok = true;
    return tlv;
}

bool is_universal(const Tlv &tlv, int tag)
{
    return tlv.ok && tlv.xclass == V_ASN1_UNIVERSAL && tlv.tag == tag;
}

struct KeyDescription
{
    std::vector<std::byte> challenge;
    bool ok{false};
};

// Walks KeyDescription's leading fields (version, level, version, level) to reach and extract the
// attestationChallenge. The level values and trailing fields (uniqueId, authorization lists) are unused.
KeyDescription parse_key_description(const unsigned char *data, long length)
{
    KeyDescription desc;

    const unsigned char *end = data + length;
    const Tlv seq = read_tlv(data, end);
    if (!is_universal(seq, V_ASN1_SEQUENCE))
    {
        return desc;
    }

    const unsigned char *field = seq.content;
    const unsigned char *seq_end = seq.content + seq.len;

    const Tlv version = read_tlv(field, seq_end);
    if (!is_universal(version, V_ASN1_INTEGER))
    {
        return desc;
    }
    field = version.next;

    const Tlv attestation_level = read_tlv(field, seq_end);
    if (!is_universal(attestation_level, V_ASN1_ENUMERATED))
    {
        return desc;
    }
    field = attestation_level.next;

    const Tlv keymint_version = read_tlv(field, seq_end);
    if (!is_universal(keymint_version, V_ASN1_INTEGER))
    {
        return desc;
    }
    field = keymint_version.next;

    const Tlv keymint_level = read_tlv(field, seq_end);
    if (!is_universal(keymint_level, V_ASN1_ENUMERATED))
    {
        return desc;
    }
    field = keymint_level.next;

    const Tlv challenge = read_tlv(field, seq_end);
    if (!is_universal(challenge, V_ASN1_OCTET_STRING))
    {
        return desc;
    }

    desc.challenge.assign(reinterpret_cast<const std::byte *>(challenge.content),
                          reinterpret_cast<const std::byte *>(challenge.content) + challenge.len);
    desc.ok = true;
    return desc;
}

std::span<const std::byte> serial_bytes(X509 *cert)
{
    const ASN1_INTEGER *serial = X509_get0_serialNumber(cert);
    if (nullptr == serial)
    {
        return {};
    }
    const auto *data = reinterpret_cast<const std::byte *>(ASN1_STRING_get0_data(serial));
    return std::span<const std::byte>{data, static_cast<std::size_t>(ASN1_STRING_length(serial))};
}

// Each verification step returns an engaged Result to stop and reject, or std::nullopt to continue.
// Ownership of every certificate/store stays in the caller's scope; helpers take non-owning
// observers or fill caller-owned out-parameters.

std::optional<AttestationVerifier::Result> parse_certificate_chain(const CertChain &cert_chain,
                                                                   std::vector<X509Ptr> &out_chain)
{
    if (cert_chain.size() < 2)
    {
        return reject("android key attestation requires a certificate chain of at least a leaf and a root");
    }
    out_chain.reserve(cert_chain.size());
    for (const std::vector<std::byte> &der : cert_chain)
    {
        X509Ptr cert = parse_der(der);
        if (nullptr == cert)
        {
            return reject("failed to parse a certificate in the attestation chain");
        }
        out_chain.push_back(std::move(cert));
    }
    return std::nullopt;
}

std::optional<AttestationVerifier::Result> build_trust_store(const AttestationVerifier::Policy &policy,
                                                             X509StorePtr &out_store)
{
    std::vector<TrustAnchor> anchors = policy.roots ? policy.roots(AttestationFormat::android_key_attestation)
                                                    : std::vector<TrustAnchor>{};
    if (anchors.empty())
    {
        return reject("no trust anchors are pinned for android key attestation");
    }

    // The public software-attestation root provides no hardware guarantee; refuse it as an anchor.
    const std::vector<std::byte> software_root_spki = [] {
        X509Ptr root = parse_pem(google_software_root_pem);
        return nullptr != root ? spki_of(root.get()) : std::vector<std::byte>{};
    }();

    out_store = X509StorePtr{X509_STORE_new(), X509_STORE_free};
    if (nullptr == out_store)
    {
        return reject("failed to allocate a certificate store");
    }
    for (const TrustAnchor &anchor : anchors)
    {
        X509Ptr cert = parse_der(anchor.der);
        if (nullptr == cert)
        {
            return reject("a pinned trust anchor could not be parsed as an X.509 certificate");
        }
        if (!software_root_spki.empty() && bytes_equal(spki_of(cert.get()), software_root_spki))
        {
            return reject("the public software-attestation root cannot be used as a trust anchor");
        }
        if (1 != X509_STORE_add_cert(out_store.get(), cert.get()))
        {
            return reject("failed to add a trust anchor to the certificate store");
        }
    }
    return std::nullopt;
}

// On success, out_verified_chain receives the built chain (owning) for the revocation check.
std::optional<AttestationVerifier::Result> validate_chain_to_pinned_root(X509_STORE *store,
                                                                         const std::vector<X509Ptr> &chain,
                                                                         const AttestationVerifier::Policy &policy,
                                                                         X509StackPtr &out_verified_chain)
{
    X509StackPtr untrusted{sk_X509_new_null(), [](STACK_OF(X509) * s) { sk_X509_free(s); }};
    if (nullptr == untrusted)
    {
        return reject("failed to allocate the intermediate certificate stack");
    }
    for (const X509Ptr &cert : chain)
    {
        sk_X509_push(untrusted.get(), cert.get());
    }

    // X509_verify_cert enforces signatures and notBefore/notAfter validity; validity is mandatory for RKP.
    X509StoreCtxPtr ctx{X509_STORE_CTX_new(), X509_STORE_CTX_free};
    if (nullptr == ctx || 1 != X509_STORE_CTX_init(ctx.get(), store, chain.front().get(), untrusted.get()))
    {
        return reject("failed to initialize certificate path validation");
    }

    const std::chrono::system_clock::time_point now =
        policy.clock ? policy.clock() : std::chrono::system_clock::now();
    X509_STORE_CTX_set_time(ctx.get(), 0, std::chrono::system_clock::to_time_t(now));

    if (1 != X509_verify_cert(ctx.get()))
    {
        const int err = X509_STORE_CTX_get_error(ctx.get());
        return reject(std::string{"certificate chain validation failed: "} + X509_verify_cert_error_string(err));
    }

    out_verified_chain = X509StackPtr{X509_STORE_CTX_get1_chain(ctx.get()),
                                      [](STACK_OF(X509) * s) { sk_X509_pop_free(s, X509_free); }};
    return std::nullopt;
}

std::optional<AttestationVerifier::Result> check_revocation(const AttestationVerifier::Policy &policy,
                                                            STACK_OF(X509) * verified_chain)
{
    // Revocation is keyed by certificate serial number.
    if (policy.is_revoked && nullptr != verified_chain)
    {
        for (int i = 0; i < sk_X509_num(verified_chain); ++i)
        {
            if (policy.is_revoked(serial_bytes(sk_X509_value(verified_chain, i))))
            {
                return reject("a certificate in the attestation chain has been revoked");
            }
        }
    }
    return std::nullopt;
}

// Reads the KeyDescription from the attestation extension nearest the root, returning the attesting
// certificate (non-owning, into chain) and the parsed description.
std::optional<AttestationVerifier::Result> extract_attestation_statement(const std::vector<X509Ptr> &chain,
                                                                         X509 *&out_attesting_cert,
                                                                         KeyDescription &out_desc)
{
    Asn1ObjectPtr oid{OBJ_txt2obj(attestation_extension_oid, 1), ASN1_OBJECT_free};
    if (nullptr == oid)
    {
        return reject("failed to build the attestation extension OID");
    }

    // Nearest-root occurrence only: an attacker who appends certificates below a genuine attestation
    // certificate cannot override the genuine (nearer-root) KeyDescription.
    X509 *attesting_cert = nullptr;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it)
    {
        if (has_attestation_extension(it->get(), oid.get()))
        {
            attesting_cert = it->get();
            break;
        }
    }
    if (nullptr == attesting_cert)
    {
        return reject("no android key attestation extension was found in the chain");
    }

    const int ext_index = X509_get_ext_by_OBJ(attesting_cert, oid.get(), -1);
    const ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(X509_get_ext(attesting_cert, ext_index));
    KeyDescription desc = parse_key_description(ASN1_STRING_get0_data(ext_data), ASN1_STRING_length(ext_data));
    if (!desc.ok)
    {
        return reject("failed to parse the KeyDescription attestation extension");
    }

    out_attesting_cert = attesting_cert;
    out_desc = std::move(desc);
    return std::nullopt;
}

std::optional<AttestationVerifier::Result> check_nonce_binding(const KeyDescription &desc,
                                                               std::span<const std::byte> expected_nonce)
{
    if (!bytes_equal(desc.challenge, expected_nonce))
    {
        return reject("the attestation challenge does not match the expected nonce");
    }
    return std::nullopt;
}

std::optional<AttestationVerifier::Result> check_key_binding(X509 *attesting_cert,
                                                             std::span<const std::byte> expected_pubkey)
{
    // Compared as canonical DER SubjectPublicKeyInfo so encodings match.
    if (!bytes_equal(spki_of(attesting_cert), expected_pubkey))
    {
        return reject("the attested public key does not match the expected key");
    }
    return std::nullopt;
}

} // namespace

std::vector<TrustAnchor> pinned_google_hardware_roots()
{
    std::vector<TrustAnchor> anchors;
    for (const char *pem : {google_hardware_root_rsa_pem, google_hardware_root_ec_pem})
    {
        X509Ptr cert = parse_pem(pem);
        if (nullptr == cert)
        {
            continue;
        }
        int size = i2d_X509(cert.get(), nullptr);
        if (size <= 0)
        {
            continue;
        }
        std::vector<std::byte> der(static_cast<std::size_t>(size));
        auto *cursor = reinterpret_cast<unsigned char *>(der.data());
        if (i2d_X509(cert.get(), &cursor) != size)
        {
            continue;
        }
        anchors.push_back(TrustAnchor{std::move(der)});
    }
    return anchors;
}

namespace detail
{

AttestationVerifier::Result verify_android_key_attestation(const AttestationEvidence &evidence,
                                                           std::span<const std::byte> expected_nonce,
                                                           std::span<const std::byte> expected_pubkey,
                                                           const AttestationVerifier::Policy &policy)
{
    if (!std::holds_alternative<CertChain>(evidence.payload))
    {
        return reject("android key attestation evidence does not carry a certificate chain");
    }
    const CertChain &cert_chain = std::get<CertChain>(evidence.payload);

    std::vector<X509Ptr> chain;
    if (std::optional<AttestationVerifier::Result> failure = parse_certificate_chain(cert_chain, chain))
    {
        return *failure;
    }

    X509StorePtr store{nullptr, X509_STORE_free};
    if (std::optional<AttestationVerifier::Result> failure = build_trust_store(policy, store))
    {
        return *failure;
    }

    X509StackPtr verified_chain{nullptr, [](STACK_OF(X509) * s) { sk_X509_pop_free(s, X509_free); }};
    if (std::optional<AttestationVerifier::Result> failure =
            validate_chain_to_pinned_root(store.get(), chain, policy, verified_chain))
    {
        return *failure;
    }

    if (std::optional<AttestationVerifier::Result> failure = check_revocation(policy, verified_chain.get()))
    {
        return *failure;
    }

    X509 *attesting_cert = nullptr;
    KeyDescription desc;
    if (std::optional<AttestationVerifier::Result> failure =
            extract_attestation_statement(chain, attesting_cert, desc))
    {
        return *failure;
    }

    if (std::optional<AttestationVerifier::Result> failure = check_nonce_binding(desc, expected_nonce))
    {
        return *failure;
    }
    if (std::optional<AttestationVerifier::Result> failure = check_key_binding(attesting_cert, expected_pubkey))
    {
        return *failure;
    }

    // No explicit security-level check: trust comes from chaining to a pinned Google hardware root
    // (the software root is refused as an anchor above), so a verified chain is hardware-backed.
    return AttestationVerifier::Result{/* ok */ true, AttestationFormat::android_key_attestation,
                                       "android key attestation verified"};
}

} // namespace detail

} // namespace mpss::attest
