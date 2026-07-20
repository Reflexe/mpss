// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Offline verifier for the Windows windows_tpm_claim "MTB1" bundle. Runs with no TPM: it parses the
// documented TCG primitives, chains the AK certificate to a pinned published Microsoft root, verifies
// the AK signature over the nonce-bound TPM2_Certify, and binds the certified subject key to the
// expected public key. All parsing is bounds-checked on hostile input and every failure denies.

#include "mpss-attest-verify/windows_tpm_claim_verifier.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

namespace mpss::attest::detail
{

namespace
{

// --- OpenSSL RAII ---
template <typename T, void (*Free)(T *)> struct Deleter
{
    void operator()(T *p) const noexcept
    {
        Free(p);
    }
};
using X509Ptr = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using StorePtr = std::unique_ptr<X509_STORE, Deleter<X509_STORE, X509_STORE_free>>;
using StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, Deleter<X509_STORE_CTX, X509_STORE_CTX_free>>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, Deleter<EVP_MD_CTX, EVP_MD_CTX_free>>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, Deleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using ParamBldPtr = std::unique_ptr<OSSL_PARAM_BLD, Deleter<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free>>;
using ParamPtr = std::unique_ptr<OSSL_PARAM, Deleter<OSSL_PARAM, OSSL_PARAM_free>>;

struct StackDeleter
{
    void operator()(STACK_OF(X509) * p) const noexcept
    {
        sk_X509_free(p); // frees the container only; the pushed certs are owned elsewhere.
    }
};
using StackPtr = std::unique_ptr<STACK_OF(X509), StackDeleter>;

constexpr AttestationFormat kFormat = AttestationFormat::windows_tpm_claim;

// TPM constants (TCG TPM 2.0).
constexpr std::uint32_t kTpmGenerated = 0xFF544347;   // "TPMG" magic prefixing every attest structure.
constexpr std::uint16_t kAttestCertify = 0x8017;      // TPM_ST_ATTEST_CERTIFY.
constexpr std::uint16_t kAlgNull = 0x0010;
constexpr std::uint16_t kAlgSha1 = 0x0004;
constexpr std::uint16_t kAlgSha256 = 0x000B;
constexpr std::uint16_t kAlgSha384 = 0x000C;
constexpr std::uint16_t kAlgSha512 = 0x000D;
constexpr std::uint16_t kAlgEcc = 0x0023;
constexpr std::uint16_t kAlgEcdsa = 0x0018;
constexpr std::uint16_t kAlgRsassa = 0x0014;
constexpr std::uint16_t kAlgRsapss = 0x0016;
constexpr std::uint16_t kEccP256 = 0x0003;
constexpr std::uint16_t kEccP384 = 0x0004;
constexpr std::uint16_t kEccP521 = 0x0005;

AttestationVerifier::Result reject(std::string reason)
{
    return AttestationVerifier::Result{/* ok */ false, kFormat, std::move(reason)};
}

const NCryptClaim *claim_from(const AttestationEvidence &evidence)
{
    return std::holds_alternative<NCryptClaim>(evidence.payload) ? &std::get<NCryptClaim>(evidence.payload) : nullptr;
}

// Bounds-checked big-endian cursor over an untrusted byte span.
class Cursor
{
  public:
    explicit Cursor(std::span<const std::byte> data) : data_{data}
    {
    }

    bool u16(std::uint16_t &out)
    {
        if (remaining() < 2)
        {
            return false;
        }
        out = static_cast<std::uint16_t>((byte(pos_) << 8) | byte(pos_ + 1));
        pos_ += 2;
        return true;
    }

    bool u32(std::uint32_t &out)
    {
        if (remaining() < 4)
        {
            return false;
        }
        out = (static_cast<std::uint32_t>(byte(pos_)) << 24) | (static_cast<std::uint32_t>(byte(pos_ + 1)) << 16) |
              (static_cast<std::uint32_t>(byte(pos_ + 2)) << 8) | static_cast<std::uint32_t>(byte(pos_ + 3));
        pos_ += 4;
        return true;
    }

    bool skip(std::size_t n)
    {
        if (remaining() < n)
        {
            return false;
        }
        pos_ += n;
        return true;
    }

    // Reads a TPM2B (uint16 length prefix + bytes) as a sub-span into the underlying buffer.
    bool tpm2b(std::span<const std::byte> &out)
    {
        std::uint16_t len = 0;
        if (!u16(len) || remaining() < len)
        {
            return false;
        }
        out = data_.subspan(pos_, len);
        pos_ += len;
        return true;
    }

    std::size_t remaining() const
    {
        return data_.size() - pos_;
    }

  private:
    std::uint8_t byte(std::size_t i) const
    {
        return std::to_integer<std::uint8_t>(data_[i]);
    }

    std::span<const std::byte> data_;
    std::size_t pos_{0};
};

struct Bundle
{
    std::span<const std::byte> tpms_attest;
    std::span<const std::byte> tpmt_signature;
    std::span<const std::byte> subject_pub; // TPMT_PUBLIC
    std::span<const std::byte> ak_cert;     // DER
};

// "MTB1" + version(1) + four little-endian length-prefixed fields.
std::optional<Bundle> parse_bundle(std::span<const std::byte> blob)
{
    static constexpr std::array<std::byte, 5> kHeader{std::byte{'M'}, std::byte{'T'}, std::byte{'B'}, std::byte{'1'},
                                                      std::byte{1}};
    if (blob.size() < kHeader.size() || !std::equal(kHeader.begin(), kHeader.end(), blob.begin()))
    {
        return std::nullopt;
    }
    std::size_t pos = kHeader.size();
    auto next = [&](std::span<const std::byte> &out) -> bool {
        if (blob.size() - pos < 4)
        {
            return false;
        }
        const std::uint32_t len = std::to_integer<std::uint32_t>(blob[pos]) |
                                  (std::to_integer<std::uint32_t>(blob[pos + 1]) << 8) |
                                  (std::to_integer<std::uint32_t>(blob[pos + 2]) << 16) |
                                  (std::to_integer<std::uint32_t>(blob[pos + 3]) << 24);
        pos += 4;
        if (blob.size() - pos < len)
        {
            return false;
        }
        out = blob.subspan(pos, len);
        pos += len;
        return true;
    };

    Bundle b;
    if (!next(b.tpms_attest) || !next(b.tpmt_signature) || !next(b.subject_pub) || !next(b.ak_cert))
    {
        return std::nullopt;
    }
    return b;
}

X509Ptr parse_cert(std::span<const std::byte> der)
{
    const unsigned char *p = reinterpret_cast<const unsigned char *>(der.data());
    return X509Ptr{d2i_X509(nullptr, &p, static_cast<long>(der.size()))};
}

// Chain the AK leaf to the pinned published root, at the policy clock if injected. The self-signed
// anchor (root) is the sole trust root; any non-self-signed pinned anchor (the ICA) is supplied as an
// intermediate, so the leaf is verified all the way to the published root -- not merely to the ICA.
bool chains_to_pinned_root(X509 *leaf, const std::vector<TrustAnchor> &anchors,
                           const AttestationVerifier::Policy &policy)
{
    StorePtr store{X509_STORE_new()};
    StackPtr intermediates{sk_X509_new_null()};
    if (!store || !intermediates)
    {
        return false;
    }
    std::vector<X509Ptr> owned; // keeps intermediate certs alive for the duration of the verify.
    bool have_root = false;
    for (const TrustAnchor &anchor : anchors)
    {
        X509Ptr ca = parse_cert(anchor.der);
        if (!ca)
        {
            return false;
        }
        const bool self_signed =
            X509_NAME_cmp(X509_get_issuer_name(ca.get()), X509_get_subject_name(ca.get())) == 0;
        if (self_signed)
        {
            if (X509_STORE_add_cert(store.get(), ca.get()) != 1) // up-refs; store owns its reference.
            {
                return false;
            }
            have_root = true;
        }
        else if (sk_X509_push(intermediates.get(), ca.get()) != 0)
        {
            owned.push_back(std::move(ca));
        }
        else
        {
            return false;
        }
    }
    if (!have_root)
    {
        return false;
    }

    StoreCtxPtr ctx{X509_STORE_CTX_new()};
    if (!ctx || X509_STORE_CTX_init(ctx.get(), store.get(), leaf, intermediates.get()) != 1)
    {
        return false;
    }
    if (policy.clock)
    {
        const auto when = std::chrono::system_clock::to_time_t(policy.clock());
        X509_STORE_CTX_set_time(ctx.get(), 0, when);
    }
    return X509_verify_cert(ctx.get()) == 1;
}

bool serial_revoked(X509 *leaf, const AttestationVerifier::Policy &policy)
{
    if (!policy.is_revoked)
    {
        return false;
    }
    const ASN1_INTEGER *asn1 = X509_get0_serialNumber(leaf);
    if (asn1 == nullptr)
    {
        return true; // no serial to check -> fail closed
    }
    const std::span<const std::byte> serial{reinterpret_cast<const std::byte *>(asn1->data),
                                            static_cast<std::size_t>(asn1->length)};
    return policy.is_revoked(serial);
}

const EVP_MD *digest_for(std::uint16_t tpm_alg)
{
    switch (tpm_alg)
    {
    case kAlgSha1:
        return EVP_sha1();
    case kAlgSha256:
        return EVP_sha256();
    case kAlgSha384:
        return EVP_sha384();
    case kAlgSha512:
        return EVP_sha512();
    default:
        return nullptr;
    }
}

// TPMT_SIGNATURE (RSA): sigAlg(2) hashAlg(2) sig(TPM2B). Verifies against the AK cert's public key.
bool signature_valid(X509 *leaf, std::span<const std::byte> attest, std::span<const std::byte> tpmt_signature)
{
    Cursor cursor{tpmt_signature};
    std::uint16_t sig_alg = 0;
    std::uint16_t hash_alg = 0;
    std::span<const std::byte> sig;
    if (!cursor.u16(sig_alg) || !cursor.u16(hash_alg) || !cursor.tpm2b(sig))
    {
        return false;
    }
    if (sig_alg != kAlgRsassa && sig_alg != kAlgRsapss)
    {
        return false;
    }
    const EVP_MD *md = digest_for(hash_alg);
    if (md == nullptr)
    {
        return false;
    }

    EVP_PKEY *ak_pubkey = X509_get0_pubkey(leaf); // borrowed
    if (ak_pubkey == nullptr)
    {
        return false;
    }
    MdCtxPtr md_ctx{EVP_MD_CTX_new()};
    if (!md_ctx)
    {
        return false;
    }
    EVP_PKEY_CTX *pctx = nullptr;
    if (EVP_DigestVerifyInit(md_ctx.get(), &pctx, md, nullptr, ak_pubkey) != 1)
    {
        return false;
    }
    if (sig_alg == kAlgRsapss)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1)
        {
            return false;
        }
    }
    return EVP_DigestVerify(md_ctx.get(), reinterpret_cast<const unsigned char *>(sig.data()), sig.size(),
                            reinterpret_cast<const unsigned char *>(attest.data()), attest.size()) == 1;
}

// TPMS_ATTEST for a CERTIFY: confirm generated-magic + type, bind the nonce, return the attested name.
std::optional<std::span<const std::byte>> parse_certify(std::span<const std::byte> attest,
                                                        std::span<const std::byte> expected_nonce)
{
    Cursor cursor{attest};
    std::uint32_t magic = 0;
    std::uint16_t type = 0;
    std::span<const std::byte> qualified_signer;
    std::span<const std::byte> extra_data;
    if (!cursor.u32(magic) || !cursor.u16(type) || !cursor.tpm2b(qualified_signer) || !cursor.tpm2b(extra_data))
    {
        return std::nullopt;
    }
    if (magic != kTpmGenerated || type != kAttestCertify)
    {
        return std::nullopt;
    }
    if (extra_data.size() != expected_nonce.size() ||
        !std::equal(extra_data.begin(), extra_data.end(), expected_nonce.begin()))
    {
        return std::nullopt;
    }
    // clockInfo(17) + firmwareVersion(8), then attested TPMS_CERTIFY_INFO: name + qualifiedName.
    std::span<const std::byte> name;
    if (!cursor.skip(17 + 8) || !cursor.tpm2b(name))
    {
        return std::nullopt;
    }
    return name;
}

// The TPM Name of an object is nameAlg || H_nameAlg(TPMT_PUBLIC). Recompute it from the subject public.
std::optional<std::vector<std::byte>> tpm_name(std::span<const std::byte> subject_pub)
{
    if (subject_pub.size() < 4)
    {
        return std::nullopt;
    }
    const std::uint16_t name_alg =
        static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(subject_pub[2]) << 8) |
                                   std::to_integer<std::uint8_t>(subject_pub[3]));
    if (name_alg != kAlgSha256)
    {
        return std::nullopt; // subject keys are SHA256-named; refuse anything else rather than guess.
    }
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char *>(subject_pub.data()), subject_pub.size(), digest.data());

    std::vector<std::byte> name;
    name.reserve(2 + digest.size());
    name.push_back(std::byte{0x00});
    name.push_back(std::byte{kAlgSha256 & 0xFF});
    for (const unsigned char b : digest)
    {
        name.push_back(static_cast<std::byte>(b));
    }
    return name;
}

const char *group_name_for(std::uint16_t curve_id)
{
    switch (curve_id)
    {
    case kEccP256:
        return "P-256";
    case kEccP384:
        return "P-384";
    case kEccP521:
        return "P-521";
    default:
        return nullptr;
    }
}

// Rebuild an EVP_PKEY from the subject TPMT_PUBLIC's ECC point so it can be compared to the expected key.
PkeyPtr subject_public_key(std::span<const std::byte> subject_pub)
{
    Cursor cursor{subject_pub};
    std::uint16_t type = 0;
    std::uint16_t name_alg = 0;
    std::uint32_t attributes = 0;
    std::span<const std::byte> auth_policy;
    if (!cursor.u16(type) || !cursor.u16(name_alg) || !cursor.u32(attributes) || !cursor.tpm2b(auth_policy))
    {
        return nullptr;
    }
    if (type != kAlgEcc)
    {
        return nullptr;
    }
    // TPMS_ECC_PARMS: symmetric, scheme, curveID, kdf.
    std::uint16_t symmetric = 0;
    if (!cursor.u16(symmetric))
    {
        return nullptr;
    }
    if (symmetric != kAlgNull)
    {
        return nullptr; // a signing key's symmetric algorithm is NULL.
    }
    std::uint16_t scheme = 0;
    if (!cursor.u16(scheme))
    {
        return nullptr;
    }
    if (scheme == kAlgEcdsa)
    {
        std::uint16_t scheme_hash = 0;
        if (!cursor.u16(scheme_hash))
        {
            return nullptr;
        }
    }
    else if (scheme != kAlgNull)
    {
        return nullptr;
    }
    std::uint16_t curve_id = 0;
    if (!cursor.u16(curve_id))
    {
        return nullptr;
    }
    std::uint16_t kdf = 0;
    if (!cursor.u16(kdf))
    {
        return nullptr;
    }
    if (kdf != kAlgNull)
    {
        std::uint16_t kdf_hash = 0;
        if (!cursor.u16(kdf_hash))
        {
            return nullptr;
        }
    }
    // unique TPMS_ECC_POINT: x, y.
    std::span<const std::byte> x;
    std::span<const std::byte> y;
    if (!cursor.tpm2b(x) || !cursor.tpm2b(y) || x.empty() || y.empty())
    {
        return nullptr;
    }
    const char *group = group_name_for(curve_id);
    if (group == nullptr)
    {
        return nullptr;
    }

    std::vector<unsigned char> point;
    point.reserve(1 + x.size() + y.size());
    point.push_back(0x04); // uncompressed
    for (const std::byte b : x)
    {
        point.push_back(std::to_integer<unsigned char>(b));
    }
    for (const std::byte b : y)
    {
        point.push_back(std::to_integer<unsigned char>(b));
    }

    ParamBldPtr bld{OSSL_PARAM_BLD_new()};
    if (!bld ||
        OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, group, 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()) != 1)
    {
        return nullptr;
    }
    ParamPtr params{OSSL_PARAM_BLD_to_param(bld.get())};
    if (!params)
    {
        return nullptr;
    }
    PkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1)
    {
        return nullptr;
    }
    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1)
    {
        return nullptr;
    }
    return PkeyPtr{raw};
}

PkeyPtr parse_spki(std::span<const std::byte> spki)
{
    const unsigned char *p = reinterpret_cast<const unsigned char *>(spki.data());
    return PkeyPtr{d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size()))};
}

bool same_public_key(std::span<const std::byte> subject_pub, std::span<const std::byte> expected_pubkey)
{
    PkeyPtr certified = subject_public_key(subject_pub);
    PkeyPtr expected = parse_spki(expected_pubkey);
    if (!certified || !expected)
    {
        return false;
    }
    return EVP_PKEY_eq(certified.get(), expected.get()) == 1;
}

} // namespace

AttestationVerifier::Result verify_windows_tpm_claim(const AttestationEvidence &evidence,
                                                     std::span<const std::byte> nonce,
                                                     std::span<const std::byte> pubkey,
                                                     const AttestationVerifier::Policy &policy)
{
    const NCryptClaim *const claim = claim_from(evidence);
    if (claim == nullptr)
    {
        return reject("windows_tpm_claim evidence does not carry an NCrypt claim payload");
    }
    if (claim->empty())
    {
        return reject("windows_tpm_claim evidence has an empty claim blob");
    }
    if (nonce.empty())
    {
        return reject("no expected nonce supplied to verify against");
    }
    if (pubkey.empty())
    {
        return reject("no expected public key supplied to verify against");
    }
    const std::vector<TrustAnchor> anchors = policy.roots ? policy.roots(kFormat) : std::vector<TrustAnchor>{};
    if (anchors.empty())
    {
        return reject("no pinned Azure vTPM root configured for windows_tpm_claim");
    }

    const std::optional<Bundle> bundle = parse_bundle(*claim);
    if (!bundle)
    {
        return reject("malformed windows_tpm_claim bundle (bad MTB1 framing)");
    }

    X509Ptr leaf = parse_cert(bundle->ak_cert);
    if (!leaf)
    {
        return reject("AK certificate did not parse as DER X.509");
    }
    if (!chains_to_pinned_root(leaf.get(), anchors, policy))
    {
        return reject("AK certificate does not chain to a pinned published Microsoft root");
    }
    if (serial_revoked(leaf.get(), policy))
    {
        return reject("AK certificate serial is revoked");
    }
    if (!signature_valid(leaf.get(), bundle->tpms_attest, bundle->tpmt_signature))
    {
        return reject("AK signature over the TPM certify structure is invalid");
    }

    const std::optional<std::span<const std::byte>> attested_name = parse_certify(bundle->tpms_attest, nonce);
    if (!attested_name)
    {
        return reject("TPM certify is malformed, not a CERTIFY, or the nonce does not match");
    }
    const std::optional<std::vector<std::byte>> computed_name = tpm_name(bundle->subject_pub);
    if (!computed_name || computed_name->size() != attested_name->size() ||
        !std::equal(computed_name->begin(), computed_name->end(), attested_name->begin()))
    {
        return reject("certified subject key name does not match the attestation");
    }
    if (!same_public_key(bundle->subject_pub, pubkey))
    {
        return reject("certified subject key does not match the expected public key");
    }

    return AttestationVerifier::Result{/* ok */ true, kFormat, "verified: subject key certified by an Azure "
                                                               "vTPM AK chaining to the published Microsoft root"};
}

} // namespace mpss::attest::detail
