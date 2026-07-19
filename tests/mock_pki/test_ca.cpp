// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tests/mock_pki/test_ca.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace mpss::tests::mock_pki
{

namespace
{

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using EvpKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using X509ExtPtr = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;

constexpr long one_year_seconds = 31536000L;

std::vector<std::byte> serialize_cert(X509 *cert)
{
    const int size = i2d_X509(cert, nullptr);
    if (size <= 0)
    {
        return {};
    }
    std::vector<std::byte> out(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(out.data());
    if (i2d_X509(cert, &cursor) != size)
    {
        return {};
    }
    return out;
}

std::vector<std::byte> serialize_spki(EVP_PKEY *key)
{
    const int size = i2d_PUBKEY(key, nullptr);
    if (size <= 0)
    {
        return {};
    }
    std::vector<std::byte> out(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(out.data());
    if (i2d_PUBKEY(key, &cursor) != size)
    {
        return {};
    }
    return out;
}

X509Ptr parse_cert(const std::vector<std::byte> &der)
{
    const auto *cursor = reinterpret_cast<const unsigned char *>(der.data());
    X509 *cert = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
    return X509Ptr{cert, X509_free};
}

bool set_common_name(X509_NAME *name, std::string_view common_name)
{
    return 1 == X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                           reinterpret_cast<const unsigned char *>(common_name.data()),
                                           static_cast<int>(common_name.size()), -1, 0);
}

bool add_basic_constraints(X509 *cert, X509 *issuer, bool is_ca)
{
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509ExtPtr ext{X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints,
                                       is_ca ? const_cast<char *>("critical,CA:TRUE") : const_cast<char *>("CA:FALSE")),
                   X509_EXTENSION_free};
    if (nullptr == ext)
    {
        return false;
    }
    return 1 == X509_add_ext(cert, ext.get(), -1);
}

// A null issuer_cert means self-signed with subject_key (a root CA).
X509Ptr build_certificate(EVP_PKEY *subject_key, X509 *issuer_cert, EVP_PKEY *issuer_key, std::string_view common_name,
                          bool is_ca, long serial)
{
    X509Ptr cert{X509_new(), X509_free};
    if (nullptr == cert)
    {
        return X509Ptr{nullptr, X509_free};
    }

    if (1 != X509_set_version(cert.get(), 2))
    {
        return X509Ptr{nullptr, X509_free};
    }
    if (1 != ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial))
    {
        return X509Ptr{nullptr, X509_free};
    }
    if (nullptr == X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0)
        || nullptr == X509_gmtime_adj(X509_getm_notAfter(cert.get()), one_year_seconds))
    {
        return X509Ptr{nullptr, X509_free};
    }
    if (1 != X509_set_pubkey(cert.get(), subject_key))
    {
        return X509Ptr{nullptr, X509_free};
    }

    X509_NAME *subject_name = X509_get_subject_name(cert.get());
    if (nullptr == subject_name || !set_common_name(subject_name, common_name))
    {
        return X509Ptr{nullptr, X509_free};
    }

    // The issuer name is either the CA's subject name (leaf) or our own (self-signed root).
    X509_NAME *issuer_name = (nullptr != issuer_cert) ? X509_get_subject_name(issuer_cert) : subject_name;
    if (nullptr == issuer_name || 1 != X509_set_issuer_name(cert.get(), issuer_name))
    {
        return X509Ptr{nullptr, X509_free};
    }

    if (!add_basic_constraints(cert.get(), (nullptr != issuer_cert) ? issuer_cert : cert.get(), is_ca))
    {
        return X509Ptr{nullptr, X509_free};
    }

    if (0 == X509_sign(cert.get(), issuer_key, EVP_sha256()))
    {
        return X509Ptr{nullptr, X509_free};
    }

    return cert;
}

} // namespace

TestKey generate_ec_key()
{
    TestKey result;

    EvpKeyCtxPtr ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free};
    if (nullptr == ctx || 1 != EVP_PKEY_keygen_init(ctx.get())
        || 1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1))
    {
        return result;
    }

    EVP_PKEY *raw = nullptr;
    if (1 != EVP_PKEY_keygen(ctx.get(), &raw))
    {
        return result;
    }
    result.pkey = EvpKeyPtr{raw, EVP_PKEY_free};
    result.spki_der = serialize_spki(result.pkey.get());
    return result;
}

TestCert create_root(const TestKey &key, std::string_view common_name)
{
    if (!key.valid())
    {
        return {};
    }
    X509Ptr cert = build_certificate(key.pkey.get(), /* issuer_cert */ nullptr, key.pkey.get(), common_name,
                                     /* is_ca */ true, /* serial */ 1);
    if (nullptr == cert)
    {
        return {};
    }
    return TestCert{serialize_cert(cert.get())};
}

TestCert create_leaf(const TestKey &subject, const TestKey &issuer_key, const TestCert &issuer_cert,
                     std::string_view common_name)
{
    if (!subject.valid() || !issuer_key.valid() || !issuer_cert.valid())
    {
        return {};
    }
    X509Ptr issuer = parse_cert(issuer_cert.der);
    if (nullptr == issuer)
    {
        return {};
    }
    X509Ptr cert = build_certificate(subject.pkey.get(), issuer.get(), issuer_key.pkey.get(), common_name,
                                     /* is_ca */ false, /* serial */ 2);
    if (nullptr == cert)
    {
        return {};
    }
    return TestCert{serialize_cert(cert.get())};
}

} // namespace mpss::tests::mock_pki
