// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/decoder.h"
#include "mpss-openssl/provider/keymgmt.h"
#include "mpss-openssl/provider/provider.h"
#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/names.h"
#include "mpss-openssl/utils/utils.h"
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string_view>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/params.h>
#include <utility>
#include <vector>

namespace
{

using namespace ::mpss_openssl::provider;
using namespace ::mpss_openssl::utils;

// mpss only issues EC keys today, so a decoded reference always yields an "EC" key object.
constexpr const char *mpss_reference_object_data_type = "EC";

// OSSL_FUNC_decoder_decode contract: 1 lets OpenSSL continue its decoder chain (a successful
// decode via object_cb, or a clean "not ours" decline); 0 is a hard error that aborts the whole
// chain and prevents other decoders from running.
constexpr int decoder_continue = 1;
constexpr int decoder_hard_error = 0;

extern "C" void *mpss_decoder_newctx(void *provctx)
{
    mpss_provider_ctx *pctx = static_cast<mpss_provider_ctx *>(provctx);
    if (nullptr == pctx)
    {
        return nullptr;
    }

    mpss_decoder_ctx *dctx = mpss_new<mpss_decoder_ctx>();
    if (nullptr == dctx)
    {
        return nullptr;
    }

    dctx->handle = pctx->handle;
    dctx->libctx = pctx->libctx;
    return dctx;
}

extern "C" void mpss_decoder_freectx(void *ctx)
{
    mpss_delete(static_cast<mpss_decoder_ctx *>(ctx));
}

extern "C" int mpss_decoder_does_selection([[maybe_unused]] void *provctx, int selection)
{
    if (0 == selection)
    {
        return 1;
    }

    return (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) ? 1 : 0;
}

bool read_core_bio(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin, std::vector<unsigned char> &out)
{
    bio_ptr in(BIO_new_from_core_bio(libctx, cin));
    if (nullptr == in)
    {
        return false;
    }

    // A valid reference fits in mpss_key_reference_max_encoded_size; read one byte past that and
    // decline anything that fills the buffer. The loop drains BIO_read's partial chunks.
    std::array<unsigned char, mpss_key_reference_max_encoded_size + 1> buffer{};
    std::size_t total = 0;
    int read_size = 0;
    while ((read_size = BIO_read(in.get(), buffer.data() + total, static_cast<int>(buffer.size() - total))) > 0)
    {
        total += static_cast<std::size_t>(read_size);
        if (buffer.size() == total)
        {
            return false;
        }
    }

    if (read_size < 0)
    {
        return false;
    }

    out.assign(buffer.begin(), buffer.begin() + total);
    return true;
}

// Parse our reference PEM object into a key_reference, or return null for any foreign or invalid PEM.
std::unique_ptr<mpss_key_reference> parse_reference_input(const std::vector<unsigned char> &input)
{
    if (input.empty() || !std::in_range<int>(input.size()))
    {
        return nullptr;
    }

    bio_ptr in(BIO_new_mem_buf(input.data(), static_cast<int>(input.size())));
    if (nullptr == in)
    {
        return nullptr;
    }

    ERR_set_mark();

    char *pem_name = nullptr;
    char *pem_header = nullptr;
    unsigned char *pem_data = nullptr;
    long pem_data_len = 0;
    const int pem_read = PEM_read_bio(in.get(), &pem_name, &pem_header, &pem_data, &pem_data_len);
    const openssl_ptr<char> pem_name_owner(pem_name);
    const openssl_ptr<char> pem_header_owner(pem_header);
    const openssl_ptr<unsigned char> pem_data_owner(pem_data);

    const bool is_mpss_reference = pem_read > 0 && nullptr != pem_name &&
                                   0 == std::strcmp(pem_name, mpss_key_reference_pem_label) && pem_data_len >= 0;
    if (!is_mpss_reference)
    {
        // Not our PEM object; discard the probe's errors and let the chain continue.
        ERR_pop_to_mark();
        return nullptr;
    }

    // It was our PEM object; drop the mark so any genuine parse errors survive.
    ERR_clear_last_mark();

    auto key_reference = std::make_unique<mpss_key_reference>();
    if (!mpss_parse_key_reference_body(
            std::span<const unsigned char>{pem_data, static_cast<std::size_t>(pem_data_len)}, *key_reference))
    {
        return nullptr;
    }

    return key_reference;
}

extern "C" int mpss_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, [[maybe_unused]] int selection,
                                   OSSL_CALLBACK *object_cb, void *object_cbarg,
                                   [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                   [[maybe_unused]] void *pw_cbarg)
{
    mpss_decoder_ctx *dctx = static_cast<mpss_decoder_ctx *>(ctx);
    if (nullptr == dctx || nullptr == object_cb)
    {
        return decoder_hard_error;
    }

    std::vector<unsigned char> input;
    if (!read_core_bio(dctx->libctx, cin, input))
    {
        // Decline oversized or unreadable input rather than aborting the chain for other decoders.
        return decoder_continue;
    }

    std::unique_ptr<mpss_key_reference> key_reference = parse_reference_input(input);
    if (nullptr == key_reference)
    {
        // Not our reference; let OpenSSL keep trying the rest of the decoder chain.
        return decoder_continue;
    }

    // Hand key management the same load reference the store loader produces (see
    // mpss_build_key_load_reference); the decoder always targets the default backend (empty). object_cb
    // consumes it synchronously, so this local buffer outlives the call.
    byte_vector reference;
    if (!mpss_build_key_load_reference(std::string_view{}, key_reference->key_name, reference))
    {
        return decoder_hard_error;
    }
    int object_type = OSSL_OBJECT_PKEY;
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 const_cast<char *>(mpss_reference_object_data_type), 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, reference.data(), reference.size());
    params[3] = OSSL_PARAM_construct_end();
    return object_cb(params, object_cbarg);
}

const OSSL_DISPATCH mpss_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, reinterpret_cast<void (*)(void)>(mpss_decoder_newctx)},
    {OSSL_FUNC_DECODER_FREECTX, reinterpret_cast<void (*)(void)>(mpss_decoder_freectx)},
    {OSSL_FUNC_DECODER_DOES_SELECTION, reinterpret_cast<void (*)(void)>(mpss_decoder_does_selection)},
    {OSSL_FUNC_DECODER_DECODE, reinterpret_cast<void (*)(void)>(mpss_decoder_decode)},
    OSSL_DISPATCH_END};

} // namespace

namespace mpss_openssl::provider
{

const OSSL_ALGORITHM mpss_decoder_algorithms[] = {
    {ec_key_names, "provider=mpss,input=pem", mpss_decoder_functions, "mpss EC reference PEM decoder"},
    {nullptr, nullptr, nullptr, nullptr}};

} // namespace mpss_openssl::provider
