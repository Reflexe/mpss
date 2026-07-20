// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tests/mock_pki/android_fixtures.h"
#include <memory>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace mpss::tests::mock_pki
{

namespace
{

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509ExtPtr = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using Asn1OctetStringPtr = std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>;
using Asn1ObjectPtr = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;

constexpr const char *attestation_extension_oid = "1.3.6.1.4.1.11129.2.1.17";

// Minimal DER encoding helpers, only enough to build a KeyDescription.

std::vector<std::byte> der_length(std::size_t length)
{
    std::vector<std::byte> out;
    if (length < 0x80)
    {
        out.push_back(static_cast<std::byte>(length));
        return out;
    }
    std::vector<std::byte> magnitude;
    while (length > 0)
    {
        magnitude.insert(magnitude.begin(), static_cast<std::byte>(length & 0xFFU));
        length >>= 8U;
    }
    out.push_back(static_cast<std::byte>(0x80U | magnitude.size()));
    out.insert(out.end(), magnitude.begin(), magnitude.end());
    return out;
}

std::vector<std::byte> der_tlv(unsigned char tag, std::span<const std::byte> content)
{
    std::vector<std::byte> out;
    out.push_back(static_cast<std::byte>(tag));
    const std::vector<std::byte> length = der_length(content.size());
    out.insert(out.end(), length.begin(), length.end());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// Big-endian INTEGER/ENUMERATED content, prepending 0x00 when the top bit would otherwise read as negative.
std::vector<std::byte> der_nonneg_content(unsigned long value)
{
    std::vector<std::byte> content;
    if (0 == value)
    {
        content.push_back(std::byte{0});
    }
    else
    {
        while (value > 0)
        {
            content.insert(content.begin(), static_cast<std::byte>(value & 0xFFU));
            value >>= 8U;
        }
        if (0 != (std::to_integer<unsigned>(content.front()) & 0x80U))
        {
            content.insert(content.begin(), std::byte{0});
        }
    }
    return content;
}

std::vector<std::byte> der_integer(unsigned long value)
{
    return der_tlv(0x02, der_nonneg_content(value));
}

std::vector<std::byte> der_enumerated(unsigned long value)
{
    return der_tlv(0x0A, der_nonneg_content(value));
}

std::vector<std::byte> der_octet_string(std::span<const std::byte> content)
{
    return der_tlv(0x04, content);
}

std::vector<std::byte> der_sequence(std::span<const std::byte> content)
{
    return der_tlv(0x30, content);
}

void append(std::vector<std::byte> &dst, const std::vector<std::byte> &src)
{
    dst.insert(dst.end(), src.begin(), src.end());
}

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

// Adds the attestation extension: an OCTET STRING wrapping the KeyDescription DER, non-critical to
// match real Android certificates.
bool add_attestation_extension(X509 *cert, const std::vector<std::byte> &key_description)
{
    Asn1ObjectPtr oid{OBJ_txt2obj(attestation_extension_oid, 1), ASN1_OBJECT_free};
    if (nullptr == oid)
    {
        return false;
    }
    Asn1OctetStringPtr value{ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free};
    if (nullptr == value
        || 1 != ASN1_OCTET_STRING_set(value.get(), reinterpret_cast<const unsigned char *>(key_description.data()),
                                      static_cast<int>(key_description.size())))
    {
        return false;
    }
    X509ExtPtr ext{X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), /* crit */ 0, value.get()),
                   X509_EXTENSION_free};
    if (nullptr == ext)
    {
        return false;
    }
    return 1 == X509_add_ext(cert, ext.get(), -1);
}

} // namespace

std::vector<std::byte> make_key_description(std::span<const std::byte> challenge, TestSecurityLevel level)
{
    const auto level_value = static_cast<unsigned long>(level);

    std::vector<std::byte> body;
    append(body, der_integer(200));                    // attestationVersion
    append(body, der_enumerated(level_value));          // attestationSecurityLevel
    append(body, der_integer(200));                    // keyMintVersion
    append(body, der_enumerated(level_value));          // keyMintSecurityLevel
    append(body, der_octet_string(challenge));          // attestationChallenge
    append(body, der_octet_string({}));                 // uniqueId (empty)
    append(body, der_sequence({}));                     // softwareEnforced (empty AuthorizationList)
    append(body, der_sequence({}));                     // hardwareEnforced (empty AuthorizationList)

    return der_sequence(body);
}

TestCert make_android_cert(const TestKey &subject, const TestKey &issuer_key, const TestCert *issuer_cert,
                           const AndroidCertOptions &opts)
{
    if (!subject.valid() || !issuer_key.valid())
    {
        return {};
    }

    X509Ptr issuer{nullptr, X509_free};
    if (nullptr != issuer_cert)
    {
        if (!issuer_cert->valid())
        {
            return {};
        }
        issuer = parse_cert(issuer_cert->der);
        if (nullptr == issuer)
        {
            return {};
        }
    }

    X509Ptr cert{X509_new(), X509_free};
    if (nullptr == cert)
    {
        return {};
    }

    if (1 != X509_set_version(cert.get(), 2)
        || 1 != ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), opts.serial)
        || nullptr == X509_gmtime_adj(X509_getm_notBefore(cert.get()), opts.not_before_offset_seconds)
        || nullptr == X509_gmtime_adj(X509_getm_notAfter(cert.get()), opts.not_after_offset_seconds)
        || 1 != X509_set_pubkey(cert.get(), subject.pkey.get()))
    {
        return {};
    }

    X509_NAME *subject_name = X509_get_subject_name(cert.get());
    if (nullptr == subject_name || !set_common_name(subject_name, opts.common_name))
    {
        return {};
    }

    X509_NAME *issuer_name = (nullptr != issuer) ? X509_get_subject_name(issuer.get()) : subject_name;
    if (nullptr == issuer_name || 1 != X509_set_issuer_name(cert.get(), issuer_name))
    {
        return {};
    }

    if (!add_basic_constraints(cert.get(), (nullptr != issuer) ? issuer.get() : cert.get(), opts.is_ca))
    {
        return {};
    }

    if (opts.key_description.has_value() && !add_attestation_extension(cert.get(), *opts.key_description))
    {
        return {};
    }

    if (0 == X509_sign(cert.get(), issuer_key.pkey.get(), EVP_sha256()))
    {
        return {};
    }

    return TestCert{serialize_cert(cert.get())};
}

std::vector<std::byte> cert_serial_bytes(const TestCert &cert)
{
    if (!cert.valid())
    {
        return {};
    }
    X509Ptr parsed = parse_cert(cert.der);
    if (nullptr == parsed)
    {
        return {};
    }
    const ASN1_INTEGER *serial = X509_get0_serialNumber(parsed.get());
    if (nullptr == serial)
    {
        return {};
    }
    const auto *data = reinterpret_cast<const std::byte *>(ASN1_STRING_get0_data(serial));
    return std::vector<std::byte>{data, data + ASN1_STRING_length(serial)};
}

} // namespace mpss::tests::mock_pki
