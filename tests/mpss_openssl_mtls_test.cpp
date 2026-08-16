// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/api.h"
#include "openssl_raii.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/bio.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

// Drains the OpenSSL error queue into a string for assertion messages.
std::string DrainOpenSslErrors()
{
    std::string out;
    unsigned long code = 0;
    while (0 != (code = ERR_get_error()))
    {
        std::array<char, 256> buffer{};
        ERR_error_string_n(code, buffer.data(), buffer.size());
        out += buffer.data();
        out += '\n';
    }
    return out.empty() ? std::string("(no OpenSSL errors)") : out;
}

// Outcome of one non-blocking SSL call over the BIO pair. `progress` carries the positive return
// value (bytes moved, or 1 for a completed handshake); 0 means the endpoint only wants more I/O and
// the caller should keep pumping.
struct SslStepResult
{
    ::testing::AssertionResult result;
    int progress = 0;
};

SslStepResult SslStep(SSL *ssl, const char *who, const char *op, int rc)
{
    if (rc > 0)
    {
        return {::testing::AssertionSuccess(), rc};
    }
    const int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
        return {::testing::AssertionSuccess(), 0};
    }
    return {::testing::AssertionFailure()
            << who << " " << op << " failed: rc=" << rc << " SSL_get_error=" << err << "\n"
            << DrainOpenSslErrors()};
}

constexpr int kMaxPumpIterations = 200;

// Drives both ends of an in-memory TLS handshake to completion, pumping each side until it finishes
// or blocks on the BIO pair.
::testing::AssertionResult DriveHandshakeToCompletion(SSL *client_ssl, SSL *server_ssl)
{
    const auto advance = [](SSL *ssl, const char *who, bool &done) -> ::testing::AssertionResult {
        if (done)
        {
            return ::testing::AssertionSuccess();
        }
        const SslStepResult step = SslStep(ssl, who, "SSL_do_handshake", SSL_do_handshake(ssl));
        done = step.progress > 0;
        return step.result;
    };

    bool client_done = false;
    bool server_done = false;
    int iterations = 0;
    for (; iterations < kMaxPumpIterations && !(client_done && server_done); ++iterations)
    {
        if (const ::testing::AssertionResult r = advance(client_ssl, "client", client_done); !r)
        {
            return r;
        }
        if (const ::testing::AssertionResult r = advance(server_ssl, "server", server_done); !r)
        {
            return r;
        }
    }
    if (!(client_done && server_done))
    {
        return ::testing::AssertionFailure()
               << "handshake did not complete after " << iterations << " iterations: client_done=" << client_done
               << " server_done=" << server_done << "\n"
               << DrainOpenSslErrors();
    }
    return ::testing::AssertionSuccess();
}

// Sends one message from a peer and verifies the other peer receives it intact, pumping partial
// SSL_write/SSL_read until the whole message transfers.
::testing::AssertionResult ExchangeMessage(SSL *from, const char *from_name, SSL *to, const char *to_name,
                                           std::string_view message)
{
    std::vector<char> buffer(message.size());
    std::size_t sent = 0;
    std::size_t received = 0;

    for (int iterations = 0; iterations < kMaxPumpIterations && received < buffer.size(); ++iterations)
    {
        // BIO_new_bio_pair connects the peers directly; retrying both SSL endpoints is the pump.
        if (sent < message.size())
        {
            const SslStepResult step =
                SslStep(from, from_name, "SSL_write",
                        SSL_write(from, message.data() + sent, static_cast<int>(message.size() - sent)));
            if (!step.result)
            {
                return step.result;
            }
            sent += static_cast<std::size_t>(step.progress);
        }

        if (received < buffer.size())
        {
            const SslStepResult step =
                SslStep(to, to_name, "SSL_read",
                        SSL_read(to, buffer.data() + received, static_cast<int>(buffer.size() - received)));
            if (!step.result)
            {
                return step.result;
            }
            received += static_cast<std::size_t>(step.progress);
        }
    }

    if (received != buffer.size())
    {
        return ::testing::AssertionFailure() << "message exchange did not complete after " << kMaxPumpIterations
                                             << " iterations: sent=" << sent << " received=" << received << "\n"
                                             << DrainOpenSslErrors();
    }

    if (message != std::string_view(buffer.data(), buffer.size()))
    {
        return ::testing::AssertionFailure() << to_name << " received a corrupted message";
    }
    return ::testing::AssertionSuccess();
}

} // namespace

namespace mpss_openssl::tests
{

using namespace mpss_openssl::testing;

class MpssMutualTlsTest : public ::testing::TestWithParam<const char *>
{
  protected:
    // Declared so RAII destruction unloads the providers before the library context is freed.
    ossl_lib_ctx_ptr libctx;
    ossl_provider_ptr mpss_prov;
    ossl_provider_ptr default_prov;
    std::vector<std::string> key_names;

    void SetUp() override
    {
        libctx.reset(OSSL_LIB_CTX_new());
        ASSERT_NE(nullptr, libctx);
        ASSERT_NE(0, OSSL_PROVIDER_add_builtin(libctx.get(), "mpss", OSSL_provider_init));
        mpss_prov.reset(OSSL_PROVIDER_load(libctx.get(), "mpss"));
        ASSERT_NE(nullptr, mpss_prov);
        default_prov.reset(OSSL_PROVIDER_load(libctx.get(), "default"));
        ASSERT_NE(nullptr, default_prov);
    }

    void TearDown() override
    {
        for (const std::string &key_name : key_names)
        {
            mpss_delete_key(key_name.c_str());
        }
    }

    std::string MakeKeyName(std::string_view label)
    {
        static std::atomic<std::uint64_t> counter{0};
        const auto ticks = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        // Keep the name under the backends' 64-char key-name limit (see MakeKeyName in the main
        // provider tests): short prefix + truncated label + compact clock/counter suffix.
        std::string key_name = "mpss_mtls_" + std::string(label.substr(0, 12)) + "_" +
                               std::to_string(ticks % 1000000000000ULL) + "_" + std::to_string(++counter);
        mpss_delete_key(key_name.c_str());
        key_names.push_back(key_name);
        return key_name;
    }

    evp_pkey_ptr GenerateMpssKey(const std::string &key_name)
    {
        evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(libctx.get(), "EC", "provider=mpss"));
        if (nullptr == ctx || 1 != EVP_PKEY_keygen_init(ctx.get()))
        {
            return nullptr;
        }

        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("mpss_key_name", const_cast<char *>(key_name.c_str()), 0),
            OSSL_PARAM_construct_utf8_string("mpss_algorithm", const_cast<char *>(GetParam()), 0), OSSL_PARAM_END};
        if (1 != EVP_PKEY_CTX_set_params(ctx.get(), params))
        {
            return nullptr;
        }

        EVP_PKEY *pkey = nullptr;
        if (1 != EVP_PKEY_generate(ctx.get(), &pkey))
        {
            return nullptr;
        }
        return evp_pkey_ptr(pkey);
    }

    // Encode the key to a reference PEM and reload it through the decoder.
    evp_pkey_ptr ReloadViaReferencePem(EVP_PKEY *key)
    {
        encoder_ctx_ptr encoder(
            OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_PRIVATE_KEY, "PEM", "MpssKeyReference", "provider=mpss"));
        if (nullptr == encoder || OSSL_ENCODER_CTX_get_num_encoders(encoder.get()) <= 0)
        {
            return nullptr;
        }

        bio_ptr mem(BIO_new(BIO_s_mem()));
        if (nullptr == mem || 1 != OSSL_ENCODER_to_bio(encoder.get(), mem.get()))
        {
            return nullptr;
        }

        char *pem_data = nullptr;
        const long pem_len = BIO_get_mem_data(mem.get(), &pem_data);
        if (pem_len <= 0 || nullptr == pem_data)
        {
            return nullptr;
        }

        bio_ptr in(BIO_new_mem_buf(pem_data, static_cast<int>(pem_len)));
        if (nullptr == in)
        {
            return nullptr;
        }
        EVP_PKEY *reloaded =
            PEM_read_bio_PrivateKey_ex(in.get(), nullptr, nullptr, nullptr, libctx.get(), "provider=mpss");
        return evp_pkey_ptr(reloaded);
    }

    // mpss binds the signature hash to the key's group, so a P-384 key must be signed with
    // SHA-384 and a P-521 key with SHA-512; signing those with SHA-256 is rejected. Fetch the
    // digest from the test's libctx (not the global default) so cert signing stays on the same
    // library context as the key and certificate.
    evp_md_ptr DigestForParam() const
    {
        static constexpr std::pair<std::string_view, const char *> kGroupDigests[] = {
            {"ecdsa_secp256r1_sha256", "SHA256"},
            {"ecdsa_secp384r1_sha384", "SHA384"},
            {"ecdsa_secp521r1_sha512", "SHA512"}};

        const std::string_view algorithm = GetParam();
        for (const auto &[name, digest_name] : kGroupDigests)
        {
            if (algorithm == name)
            {
                return evp_md_ptr(EVP_MD_fetch(libctx.get(), digest_name, nullptr));
            }
        }
        return nullptr;
    }

    x509_ptr BuildSelfSignedCert(EVP_PKEY *key, const std::string &common_name, const char *extended_key_usage)
    {
        x509_ptr cert(X509_new_ex(libctx.get(), nullptr));
        if (nullptr == cert)
        {
            return nullptr;
        }
        X509_NAME *name = X509_get_subject_name(cert.get());
        if (nullptr == name)
        {
            return nullptr;
        }

        const bool populated =
            1 == X509_set_version(cert.get(), 2) && 1 == ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) &&
            nullptr != X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) &&
            nullptr != X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600) && 1 == X509_set_pubkey(cert.get(), key) &&
            1 == X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                            reinterpret_cast<const unsigned char *>(common_name.c_str()), -1, -1, 0) &&
            1 == X509_set_issuer_name(cert.get(), name);
        if (!populated)
        {
            return nullptr;
        }

        X509V3_CTX v3ctx;
        X509V3_set_ctx(&v3ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
        const auto add_ext = [&](int nid, const char *value) -> bool {
            X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, nid, value);
            if (nullptr == ext)
            {
                return false;
            }
            const bool ok = 1 == X509_add_ext(cert.get(), ext, -1);
            X509_EXTENSION_free(ext);
            return ok;
        };

        // Self-signed leaf that is also its own trust anchor for the peer.
        const bool extended = add_ext(NID_basic_constraints, "critical,CA:TRUE") &&
                              add_ext(NID_key_usage, "critical,digitalSignature,keyCertSign") &&
                              add_ext(NID_ext_key_usage, extended_key_usage);
        if (!extended)
        {
            return nullptr;
        }

        const evp_md_ptr digest = DigestForParam();
        if (nullptr == digest || X509_sign(cert.get(), key, digest.get()) <= 0)
        {
            return nullptr;
        }
        return cert;
    }

    // Builds a TLS 1.3 context that authenticates with the given cert + key and requires the peer's cert.
    ssl_ctx_ptr MakeTlsContext(const SSL_METHOD *method, X509 *cert, EVP_PKEY *key, X509 *peer_cert, int verify_mode)
    {
        ssl_ctx_ptr ctx(SSL_CTX_new_ex(libctx.get(), nullptr, method));
        if (nullptr == ctx)
        {
            return nullptr;
        }
        if (1 != SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) ||
            1 != SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION))
        {
            return nullptr;
        }
        // No session tickets: keeps post-handshake traffic out of the in-memory data exchange.
        SSL_CTX_set_num_tickets(ctx.get(), 0);
        if (1 != SSL_CTX_use_certificate(ctx.get(), cert) || 1 != SSL_CTX_use_PrivateKey(ctx.get(), key))
        {
            return nullptr;
        }
        if (1 != X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx.get()), peer_cert))
        {
            return nullptr;
        }
        SSL_CTX_set_verify(ctx.get(), verify_mode, nullptr);
        return ctx;
    }
};

// Scenario: two peers each authenticate a full mutual-TLS 1.3 handshake with an MPSS-provider
// key + cert, where each private key was persisted to a reference PEM and reloaded through the
// MPSS decoder before use (the reference-codec round-trip driving a live handshake).
// Expected behavior: the handshake completes, both peers verify each other's certificate
// (X509_V_OK) and identity, and encrypted application data flows in both directions.
TEST_P(MpssMutualTlsTest, MutualHandshakeWithReferenceReloadedKeys)
{
    if (!mpss_is_algorithm_available(GetParam()))
    {
        GTEST_SKIP() << "Algorithm " << GetParam() << " not supported by current backend";
    }

    evp_pkey_ptr server_key = GenerateMpssKey(MakeKeyName("server"));
    evp_pkey_ptr client_key = GenerateMpssKey(MakeKeyName("client"));
    if (nullptr == server_key || nullptr == client_key)
    {
        GTEST_SKIP() << "MPSS provider key generation failed: " << mpss_get_error();
    }

    // Persist each key as a reference PEM and reload it through the decoder; the reloaded keys
    // are what actually authenticate the handshake below.
    evp_pkey_ptr server_key_reloaded = ReloadViaReferencePem(server_key.get());
    evp_pkey_ptr client_key_reloaded = ReloadViaReferencePem(client_key.get());
    ASSERT_NE(nullptr, server_key_reloaded) << "server key reference round-trip failed: " << DrainOpenSslErrors();
    ASSERT_NE(nullptr, client_key_reloaded) << "client key reference round-trip failed: " << DrainOpenSslErrors();

    // Build each certificate from the reloaded key that will authenticate with it.
    x509_ptr server_cert = BuildSelfSignedCert(server_key_reloaded.get(), "localhost", "serverAuth");
    x509_ptr client_cert = BuildSelfSignedCert(client_key_reloaded.get(), "mpss-client", "clientAuth");
    ASSERT_NE(nullptr, server_cert) << "server cert build failed: " << DrainOpenSslErrors();
    ASSERT_NE(nullptr, client_cert) << "client cert build failed: " << DrainOpenSslErrors();

    // Each endpoint authenticates with its own MPSS key + cert and requires the peer's certificate.
    // The cert/key consistency check inside SSL_CTX_use_PrivateKey only passes because each cert was
    // built above from the same reloaded key (the provider implements no keymgmt match).
    ssl_ctx_ptr server_ctx = MakeTlsContext(TLS_server_method(), server_cert.get(), server_key_reloaded.get(),
                                            client_cert.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
    ssl_ctx_ptr client_ctx = MakeTlsContext(TLS_client_method(), client_cert.get(), client_key_reloaded.get(),
                                            server_cert.get(), SSL_VERIFY_PEER);
    ASSERT_NE(nullptr, server_ctx) << "server context setup failed: " << DrainOpenSslErrors();
    ASSERT_NE(nullptr, client_ctx) << "client context setup failed: " << DrainOpenSslErrors();

    ssl_ptr server_ssl(SSL_new(server_ctx.get()));
    ssl_ptr client_ssl(SSL_new(client_ctx.get()));
    ASSERT_NE(nullptr, server_ssl);
    ASSERT_NE(nullptr, client_ssl);

    BIO *client_bio = nullptr;
    BIO *server_bio = nullptr;
    ASSERT_EQ(1, BIO_new_bio_pair(&client_bio, 1U << 20U, &server_bio, 1U << 20U));
    // SSL takes ownership of the BIO ends.
    SSL_set_bio(client_ssl.get(), client_bio, client_bio);
    SSL_set_bio(server_ssl.get(), server_bio, server_bio);
    SSL_set_connect_state(client_ssl.get());
    SSL_set_accept_state(server_ssl.get());

    ASSERT_TRUE(DriveHandshakeToCompletion(client_ssl.get(), server_ssl.get()));

    const long client_verify = SSL_get_verify_result(client_ssl.get());
    EXPECT_EQ(X509_V_OK, client_verify) << "client verify result: " << X509_verify_cert_error_string(client_verify);
    const long server_verify = SSL_get_verify_result(server_ssl.get());
    EXPECT_EQ(X509_V_OK, server_verify) << "server verify result: " << X509_verify_cert_error_string(server_verify);
    EXPECT_EQ(TLS1_3_VERSION, SSL_version(client_ssl.get()))
        << "negotiated protocol: " << SSL_get_version(client_ssl.get());

    x509_ptr client_seen_peer(SSL_get1_peer_certificate(client_ssl.get()));
    x509_ptr server_seen_peer(SSL_get1_peer_certificate(server_ssl.get()));
    ASSERT_NE(nullptr, client_seen_peer) << "client received no peer certificate";
    ASSERT_NE(nullptr, server_seen_peer) << "server received no peer certificate (mutual auth)";
    EXPECT_EQ(0, X509_cmp(client_seen_peer.get(), server_cert.get())) << "client saw an unexpected server certificate";
    EXPECT_EQ(0, X509_cmp(server_seen_peer.get(), client_cert.get())) << "server saw an unexpected client certificate";

    // Application data flows both ways over the established session.
    EXPECT_TRUE(ExchangeMessage(client_ssl.get(), "client", server_ssl.get(), "server", "ping-from-mpss-client"));
    EXPECT_TRUE(ExchangeMessage(server_ssl.get(), "server", client_ssl.get(), "client", "pong-from-mpss-server"));
}

INSTANTIATE_TEST_SUITE_P(EcAlgorithms, MpssMutualTlsTest,
                         ::testing::Values("ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
                                           "ecdsa_secp521r1_sha512"),
                         [](const ::testing::TestParamInfo<const char *> &info) { return std::string(info.param); });

} // namespace mpss_openssl::tests
