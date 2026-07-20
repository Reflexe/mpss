// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-attest-verify/verify_apple_acme.h"
#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace mpss::attest::apple
{

namespace
{

using Result = AttestationVerifier::Result;
using Policy = AttestationVerifier::Policy;

// sk_X509_free is inline (no address to take) and frees only the stack, not the held certs.
struct StackDeleter
{
    void operator()(STACK_OF(X509) * sk) const
    {
        sk_X509_free(sk);
    }
};

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;
using StackPtr = std::unique_ptr<STACK_OF(X509), StackDeleter>;
using EvpKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

// Apple MDA nonce extension; its value is SHA-256(the ACME token).
constexpr const char *apple_challenge_nonce_oid = "1.2.840.113635.100.8.11.1";

Result reject(std::string reason)
{
    return Result{/* ok */ false, AttestationFormat::apple_acme_managed_device, std::move(reason)};
}

X509Ptr parse_cert(const std::vector<std::byte> &der)
{
    const auto *cursor = reinterpret_cast<const unsigned char *>(der.data());
    X509 *cert = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
    return X509Ptr{cert, X509_free};
}

// Reads the leaf's ACME nonce extension value (extnValue octet-string content); false if absent.
bool find_nonce_extension_value(X509 *leaf, std::vector<std::byte> &out)
{
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid{
        OBJ_txt2obj(apple_challenge_nonce_oid, /* no_name */ 1), ASN1_OBJECT_free};
    if (nullptr == oid)
    {
        return false;
    }

    const int count = X509_get_ext_count(leaf);
    for (int i = 0; i < count; ++i)
    {
        X509_EXTENSION *ext = X509_get_ext(leaf, i);
        if (nullptr == ext)
        {
            continue;
        }
        if (0 != OBJ_cmp(X509_EXTENSION_get_object(ext), oid.get()))
        {
            continue;
        }
        const ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ext);
        if (nullptr == data)
        {
            return false;
        }
        const unsigned char *bytes = ASN1_STRING_get0_data(data);
        const int len = ASN1_STRING_length(data);
        out.assign(reinterpret_cast<const std::byte *>(bytes), reinterpret_cast<const std::byte *>(bytes) + len);
        return true;
    }
    return false;
}

bool sha256(std::span<const std::byte> in, std::vector<std::byte> &out)
{
    out.resize(SHA256_DIGEST_LENGTH);
    unsigned int len = 0;
    if (1 !=
        EVP_Digest(in.data(), in.size(), reinterpret_cast<unsigned char *>(out.data()), &len, EVP_sha256(), nullptr))
    {
        return false;
    }
    return len == SHA256_DIGEST_LENGTH;
}

bool constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    // CRYPTO_memcmp returns 0 when the buffers are equal.
    return 0 == CRYPTO_memcmp(a.data(), b.data(), a.size());
}

// Canonical DER SubjectPublicKeyInfo of the leaf's public key.
bool leaf_spki(X509 *leaf, std::vector<std::byte> &out)
{
    EvpKeyPtr pkey{X509_get_pubkey(leaf), EVP_PKEY_free};
    if (nullptr == pkey)
    {
        return false;
    }
    const int size = i2d_PUBKEY(pkey.get(), nullptr);
    if (size <= 0)
    {
        return false;
    }
    out.resize(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(out.data());
    return i2d_PUBKEY(pkey.get(), &cursor) == size;
}

// The chain (leaf-first) verifies to one of the pinned roots at the given verification time.
Result verify_chain(X509 *leaf, const std::vector<X509Ptr> &intermediates, const std::vector<X509Ptr> &roots,
                    std::time_t verify_time)
{
    X509StorePtr store{X509_STORE_new(), X509_STORE_free};
    if (nullptr == store)
    {
        return reject("failed to allocate certificate store");
    }
    for (const X509Ptr &root : roots)
    {
        if (1 != X509_STORE_add_cert(store.get(), root.get()))
        {
            return reject("failed to add pinned Apple root to certificate store");
        }
    }

    StackPtr untrusted{sk_X509_new_null()};
    if (nullptr == untrusted)
    {
        return reject("failed to allocate intermediate stack");
    }
    for (const X509Ptr &intermediate : intermediates)
    {
        if (0 == sk_X509_push(untrusted.get(), intermediate.get()))
        {
            return reject("failed to stage intermediate certificate");
        }
    }

    X509StoreCtxPtr ctx{X509_STORE_CTX_new(), X509_STORE_CTX_free};
    if (nullptr == ctx || 1 != X509_STORE_CTX_init(ctx.get(), store.get(), leaf, untrusted.get()))
    {
        return reject("failed to initialize certificate verification context");
    }

    // Pin the verification time so captured vectors replay deterministically and expiry is enforced.
    X509_STORE_CTX_set_time(ctx.get(), 0, verify_time);

    if (1 != X509_verify_cert(ctx.get()))
    {
        const int err = X509_STORE_CTX_get_error(ctx.get());
        return reject(std::string{"certificate chain did not verify to the pinned Apple root: "} +
                      X509_verify_cert_error_string(err));
    }

    return Result{/* ok */ true, AttestationFormat::apple_acme_managed_device, {}};
}

std::optional<Result> parse_leaf_and_intermediates(const CertChain &chain, X509Ptr &leaf_out,
                                                   std::vector<X509Ptr> &intermediates_out)
{
    leaf_out = parse_cert(chain.front());
    if (nullptr == leaf_out)
    {
        return reject("failed to parse Apple ACME leaf certificate");
    }
    for (std::size_t i = 1; i < chain.size(); ++i)
    {
        X509Ptr cert = parse_cert(chain[i]);
        if (nullptr == cert)
        {
            return reject("failed to parse Apple ACME intermediate certificate");
        }
        intermediates_out.push_back(std::move(cert));
    }
    return std::nullopt;
}

std::optional<Result> parse_pinned_roots(const Policy &policy, std::vector<X509Ptr> &roots_out)
{
    std::vector<TrustAnchor> anchors =
        policy.roots ? policy.roots(AttestationFormat::apple_acme_managed_device) : std::vector<TrustAnchor>{};
    if (anchors.empty())
    {
        return reject("no pinned Apple attestation root configured");
    }
    for (const TrustAnchor &anchor : anchors)
    {
        X509Ptr root = parse_cert(anchor.der);
        if (nullptr == root)
        {
            return reject("failed to parse pinned Apple attestation root");
        }
        roots_out.push_back(std::move(root));
    }
    return std::nullopt;
}

// Chain must validate to a pinned root before any leaf content (nonce/key) is trusted.
Result validate_chain_to_pinned_root(X509 *leaf, const std::vector<X509Ptr> &intermediates, const Policy &policy)
{
    std::vector<X509Ptr> roots;
    if (std::optional<Result> rejected = parse_pinned_roots(policy, roots))
    {
        return *rejected;
    }
    const std::time_t verify_time =
        policy.clock ? std::chrono::system_clock::to_time_t(policy.clock()) : std::time(nullptr);
    return verify_chain(leaf, intermediates, roots, verify_time);
}

std::optional<Result> check_nonce_binding(X509 *leaf, std::span<const std::byte> expected_nonce)
{
    std::vector<std::byte> nonce_ext;
    if (!find_nonce_extension_value(leaf, nonce_ext))
    {
        return reject("Apple ACME nonce extension (1.2.840.113635.100.8.11.1) not found in leaf");
    }
    std::vector<std::byte> expected_nonce_digest;
    if (!sha256(expected_nonce, expected_nonce_digest))
    {
        return reject("failed to hash expected nonce");
    }
    if (!constant_time_equal(nonce_ext, expected_nonce_digest))
    {
        return reject("Apple ACME nonce mismatch");
    }
    return std::nullopt;
}

std::optional<Result> check_key_binding(X509 *leaf, std::span<const std::byte> expected_pubkey)
{
    std::vector<std::byte> spki;
    if (!leaf_spki(leaf, spki))
    {
        return reject("failed to extract leaf public key");
    }
    if (!constant_time_equal(spki, expected_pubkey))
    {
        return reject("attested key does not match the expected public key");
    }
    return std::nullopt;
}

std::optional<Result> check_revocation(X509 *leaf, const Policy &policy)
{
    if (!policy.is_revoked)
    {
        return std::nullopt;
    }
    const ASN1_INTEGER *serial = X509_get0_serialNumber(leaf);
    if (nullptr == serial)
    {
        return std::nullopt;
    }
    const auto *bytes = reinterpret_cast<const std::byte *>(ASN1_STRING_get0_data(serial));
    const std::span<const std::byte> serial_span{bytes, static_cast<std::size_t>(ASN1_STRING_length(serial))};
    if (policy.is_revoked(serial_span))
    {
        return reject("Apple ACME leaf certificate is revoked");
    }
    return std::nullopt;
}

} // namespace

Result verify_apple_acme_managed_device(const AttestationEvidence &evidence, std::span<const std::byte> expected_nonce,
                                        std::span<const std::byte> expected_pubkey, const Policy &policy)
{
    if (AttestationFormat::apple_acme_managed_device != evidence.format)
    {
        return reject("evidence is not Apple ACME managed device attestation");
    }
    if (!std::holds_alternative<CertChain>(evidence.payload))
    {
        return reject("Apple ACME evidence payload is not a certificate chain");
    }
    const CertChain &cert_chain = std::get<CertChain>(evidence.payload);
    if (cert_chain.empty())
    {
        return reject("Apple ACME evidence has an empty certificate chain");
    }
    if (expected_pubkey.empty())
    {
        return reject("no expected public key was supplied");
    }
    if (expected_nonce.empty())
    {
        return reject("no expected nonce was supplied");
    }

    X509Ptr leaf{nullptr, X509_free};
    std::vector<X509Ptr> intermediates;
    if (std::optional<Result> rejected = parse_leaf_and_intermediates(cert_chain, leaf, intermediates))
    {
        return *rejected;
    }

    const Result chain_result = validate_chain_to_pinned_root(leaf.get(), intermediates, policy);
    if (!chain_result.ok)
    {
        return chain_result;
    }

    if (std::optional<Result> rejected = check_nonce_binding(leaf.get(), expected_nonce))
    {
        return *rejected;
    }
    if (std::optional<Result> rejected = check_key_binding(leaf.get(), expected_pubkey))
    {
        return *rejected;
    }
    if (std::optional<Result> rejected = check_revocation(leaf.get(), policy))
    {
        return *rejected;
    }

    return chain_result;
}

} // namespace mpss::attest::apple
