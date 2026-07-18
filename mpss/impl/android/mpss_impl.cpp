// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_keypair.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/impl/os_backend.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <optional>
#include <vector>

using jni_class = mpss::impl::os::utils::JNIObj<jclass>;
using jni_string = mpss::impl::os::utils::JNIObj<jstring>;
using jni_object = mpss::impl::os::utils::JNIObj<jobject>;
using jni_bytearray = mpss::impl::os::utils::JNIObj<jbyteArray>;

namespace
{

constexpr const char *unknown_storage = "Unknown";
constexpr const char *software_storage = "Software";
constexpr const char *trusted_storage = "Trusted Environment";
constexpr const char *strongbox_storage = "StrongBox";
constexpr const char *unknown_secure_storage = "Unknown Secure";

bool DeleteKeyOnFailure(std::string_view name)
{
    mpss::impl::os::JNIEnvGuard guard;
    jni_class km(guard.Env(), mpss::impl::os::utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        return false;
    }

    jmethodID mi = guard->GetStaticMethodID(km.get(), "DeleteKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (nullptr == mi)
    {
        return false;
    }

    const std::string key_name{name};
    jni_string keyName(guard.Env(), guard->NewStringUTF(key_name.c_str()));
    if (keyName.is_null())
    {
        return false;
    }

    jni_object result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mi, keyName.get()));
    return !result.is_null() && mpss::impl::os::utils::UnboxBoolean(guard.Env(), result.get());
}

std::vector<std::vector<std::byte>> GetAttestationCertChain(std::string_view name)
{
    mpss::impl::os::JNIEnvGuard guard;
    jni_class km(guard.Env(), mpss::impl::os::utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        return {};
    }

    jmethodID mid = guard->GetStaticMethodID(km.get(), "GetAttestationCertificateChain",
                                             "(Ljava/lang/String;)[[B");
    if (nullptr == mid)
    {
        return {};
    }

    const std::string key_name{name};
    jni_string keyName(guard.Env(), guard->NewStringUTF(key_name.c_str()));
    if (keyName.is_null())
    {
        return {};
    }

    jobjectArray result =
        reinterpret_cast<jobjectArray>(guard->CallStaticObjectMethod(km.get(), mid, keyName.get()));
    if (nullptr == result)
    {
        return {};
    }

    const jsize len = guard->GetArrayLength(result);
    std::vector<std::vector<std::byte>> chain;
    chain.reserve(static_cast<std::size_t>(len));

    for (jsize i = 0; i < len; ++i)
    {
        auto *entry = static_cast<jbyteArray>(guard->GetObjectArrayElement(result, i));
        if (nullptr == entry)
        {
            continue;
        }

        const jsize cert_len = guard->GetArrayLength(entry);
        std::vector<jbyte> bytes(static_cast<std::size_t>(cert_len));
        guard->GetByteArrayRegion(entry, 0, cert_len, bytes.data());

        std::vector<std::byte> cert(bytes.size());
        std::transform(bytes.begin(), bytes.end(), cert.begin(), [](auto b) { return static_cast<std::byte>(b); });
        chain.emplace_back(std::move(cert));
        guard->DeleteLocalRef(entry);
    }

    return chain;
}

std::vector<std::byte> BuildAndroidAttestationStatement(std::span<const std::byte> challenge,
                                                        std::span<const std::byte> public_key)
{
    static constexpr std::string_view prefix = "MPSS_ANDROID_KEY_ATTESTATION_V1";
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

void GetKeyProperties(std::string_view name, bool &hardware_backed, const char **storage_description)
{
    hardware_backed = false;
    *storage_description = nullptr;

    mpss::impl::os::JNIEnvGuard guard;
    jni_class km(guard.Env(), mpss::impl::os::utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class");
        return;
    }

    jmethodID mid = guard->GetStaticMethodID(km.get(), "GetKeySecurityLevel", "(Ljava/lang/String;)I");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetKeySecurityLevel Java method");
        return;
    }

    const std::string keyNameStr(name);
    jni_string keyName(guard.Env(), guard->NewStringUTF(keyNameStr.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String");
        return;
    }

    const jint result = guard->CallStaticIntMethod(km.get(), mid, keyName.get());
    if (-1 == result)
    {
        mpss::utils::log_and_set_error("Error calling KeyManagement.GetKeySecurityLevel Java method");
        return;
    }

    switch (result)
    {
    case 0:
        hardware_backed = false;
        *storage_description = unknown_storage;
        return;
    case 1:
        hardware_backed = false;
        *storage_description = software_storage;
        return;
    case 2:
        hardware_backed = true;
        *storage_description = unknown_secure_storage;
        return;
    case 3:
        hardware_backed = true;
        *storage_description = trusted_storage;
        return;
    case 4:
        hardware_backed = true;
        *storage_description = strongbox_storage;
        return;
    default:
        mpss::utils::log_and_set_error("Unknown result from KeyManagement.GetKeySecurityLevel");
        return;
    }
}

} // namespace

namespace mpss::impl::os
{

using enum Algorithm;

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm,
                                    std::optional<AttestationRequest> attestation);

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_warning("Key name cannot be empty.");
        return nullptr;
    }

    mpss::utils::log_trace("Attempting to open key '{}' on Android backend.", name);

    JNIEnvGuard guard;
    jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    const std::string nameStr{name};
    jni_string keyName(guard.Env(), guard->NewStringUTF(nameStr.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not create key name Java string.");
        return nullptr;
    }

    jmethodID mid = guard->GetStaticMethodID(km.get(), "OpenKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.OpenKey Java method.");
        return nullptr;
    }

    jni_object result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid, keyName.get()));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.OpenKey returned null.");
        return nullptr;
    }

    if (!utils::UnboxBoolean(guard.Env(), result.get()))
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
        return nullptr;
    }

    // Now we need the Algorithm.
    jmethodID mid_algo = guard->GetStaticMethodID(km.get(), "GetKeyAlgorithm",
                                                  "(Ljava/lang/String;)Lcom/microsoft/research/mpss/Algorithm;");
    if (nullptr == mid_algo)
    {
        mpss::utils::log_and_set_error("Failed to get KeyManagement.GetKeyAlgorithm method.");
        return nullptr;
    }

    jni_object algo_result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid_algo, keyName.get()));
    if (algo_result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.GetKeyAlgorithm returned null.");
        return nullptr;
    }

    jni_class algo_class(guard.Env(), guard->GetObjectClass(algo_result.get()));
    if (algo_class.is_null())
    {
        mpss::utils::log_and_set_error("Failed to get Java class for Algorithm.");
        return nullptr;
    }

    jmethodID nameMethod = guard->GetMethodID(algo_class.get(), "name", "()Ljava/lang/String;");
    if (nullptr == nameMethod)
    {
        mpss::utils::log_and_set_error("Could not get method id for Algorithm.name.");
        return nullptr;
    }

    jni_string algo_name(guard.Env(),
                         reinterpret_cast<jstring>(guard->CallObjectMethod(algo_result.get(), nameMethod)));
    if (algo_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not get name of enum Algorithm.");
        return nullptr;
    }

    const std::string algo_name_str = mpss::impl::os::utils::GetString(guard.Env(), algo_name.get());
    Algorithm algorithm = unsupported;

    if (algo_name_str == "secp256r1")
    {
        algorithm = ecdsa_secp256r1_sha256;
    }
    else if (algo_name_str == "secp384r1")
    {
        algorithm = ecdsa_secp384r1_sha384;
    }
    else if (algo_name_str == "secp521r1")
    {
        algorithm = ecdsa_secp521r1_sha512;
    }

    bool hardware_backed = false;
    const char *storage_description = nullptr;
    GetKeyProperties(name, hardware_backed, &storage_description);

    if (nullptr == storage_description)
    {
        // Error happened getting key properties. This is reported by GetKeyProperties, so we just return here.
        return nullptr;
    }

    // Finally, we can return the key.
    mpss::utils::log_trace("Key '{}' opened on Android with {} storage.", name, storage_description);
    return std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description, hardware_backed);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
{
    return create_key(name, algorithm, std::nullopt);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm,
                                    std::optional<AttestationRequest> attestation)
{
    if (name.empty())
    {
        mpss::utils::log_warning("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warning("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    // Check if the key already exists
    std::unique_ptr<KeyPair> existingKey = open_key(name);
    if (nullptr != existingKey)
    {
        mpss::utils::log_warning("Key '{}' already exists.", name);
        return nullptr;
    }

    mpss::utils::log_trace("Creating key '{}' with algorithm '{}' on Android backend.", name,
                           get_algorithm_info(algorithm).type_str);

    JNIEnvGuard guard;
    jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    jmethodID mid = guard->GetStaticMethodID(
        km.get(), "CreateKey", "(Ljava/lang/String;Lcom/microsoft/research/mpss/Algorithm;[B)Ljava/lang/Boolean;");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CreateKey Java method.");
        return nullptr;
    }

    const std::string keyNameStr(name);
    jni_string keyName(guard.Env(), guard->NewStringUTF(keyNameStr.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String.");
        return nullptr;
    }

    jni_class algorithmClass(guard.Env(), guard->FindClass("com/microsoft/research/mpss/Algorithm"));
    if (algorithmClass.is_null())
    {
        mpss::utils::log_and_set_error("Could not get Algorithm Java class.");
        return nullptr;
    }

    jfieldID algoFieldId = nullptr;

    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        algoFieldId =
            guard->GetStaticFieldID(algorithmClass.get(), "secp256r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp384r1_sha384:
        algoFieldId =
            guard->GetStaticFieldID(algorithmClass.get(), "secp384r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp521r1_sha512:
        algoFieldId =
            guard->GetStaticFieldID(algorithmClass.get(), "secp521r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    default:
        mpss::utils::log_warning("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (nullptr == algoFieldId)
    {
        mpss::utils::log_and_set_error("Could not find appropriate enum value for Algorithm.");
        return nullptr;
    }

    jni_object algorithmValue(guard.Env(), guard->GetStaticObjectField(algorithmClass.get(), algoFieldId));
    if (algorithmValue.is_null())
    {
        mpss::utils::log_and_set_error("Could not get object for Algorithm value.");
        return nullptr;
    }

    jbyteArray challenge_array = nullptr;
    if (attestation.has_value())
    {
        challenge_array = utils::ToJByteArray(guard.Env(), attestation->challenge);
        if (nullptr == challenge_array)
        {
            mpss::utils::log_and_set_error("Could not convert attestation challenge to jbyte array.");
            return nullptr;
        }
    }

    jni_object result(guard.Env(),
                      guard->CallStaticObjectMethod(km.get(), mid, keyName.get(), algorithmValue.get(),
                                                    challenge_array));
    if (nullptr != challenge_array)
    {
        guard->DeleteLocalRef(challenge_array);
    }
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.CreateKey returned null.");
        return nullptr;
    }

    if (!utils::UnboxBoolean(guard.Env(), result.get()))
    {
        // Error happened in Java side.
        mpss::utils::log_and_set_error(mpss::impl::os::utils::GetError(guard.Env()));
        return nullptr;
    }

    bool hardware_backed = false;
    const char *storage_description = nullptr;
    GetKeyProperties(name, hardware_backed, &storage_description);

    if (nullptr == storage_description)
    {
        // Error happened getting key properties. This is reported by GetKeyProperties, so we just return here.
        return nullptr;
    }

    std::optional<AttestationEvidence> evidence = std::nullopt;
    if (attestation.has_value() && hardware_backed)
    {
        auto cert_chain = GetAttestationCertChain(name);
        if (!cert_chain.empty())
        {
            auto key = std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description,
                                                        hardware_backed);
            const std::size_t key_size = key->extract_key({});
            std::vector<std::byte> public_key(key_size);
            if (0 == key->extract_key(public_key))
            {
                public_key.clear();
            }

            AttestationEvidence generated{};
            generated.format = AttestationFormat::android_key_attestation;
            generated.statement = BuildAndroidAttestationStatement(attestation->challenge, public_key);
            generated.cert_chain = std::move(cert_chain);
            evidence = std::move(generated);
        }
    }

    if (attestation.has_value() && AttestationRequirement::require == attestation->requirement && !evidence.has_value())
    {
        const bool deleted = DeleteKeyOnFailure(name);
        if (!deleted)
        {
            mpss::utils::log_warning("Failed to delete Android key '{}' after required attestation failure.", name);
        }
        mpss::utils::log_and_set_error("Required Android key attestation could not be produced.");
        return nullptr;
    }

    mpss::utils::log_trace("Key '{}' created on Android with {} storage.", name, storage_description);
    return std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description, hardware_backed,
                                            std::move(evidence));
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_warning("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warning("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return false;
    }

    // Check hash length.
    if (!mpss::utils::check_exact_hash_size(hash, algorithm))
    {
        return false;
    }

    JNIEnvGuard guard;

    jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID mid = guard->GetStaticMethodID(km.get(), "VerifySignature", "([B[B[B)Ljava/lang/Boolean;");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature Java method.");
        return false;
    }

    jni_bytearray hash_arr(guard.Env(), utils::ToJByteArray(guard.Env(), hash));
    if (hash_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert hash to jbyte array.");
        return false;
    }

    jni_bytearray pk_arr(guard.Env(), utils::ToJByteArray(guard.Env(), public_key));
    if (pk_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert public key to jbyte array.");
        return false;
    }

    jni_bytearray sig_arr(guard.Env(), utils::ToJByteArray(guard.Env(), sig));
    if (sig_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert signature to jbyte array.");
        return false;
    }

    jni_object result(guard.Env(),
                      guard->CallStaticObjectMethod(km.get(), mid, hash_arr.get(), sig_arr.get(), pk_arr.get()));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.VerifySignature returned null.");
        return false;
    }

    const bool verified = utils::UnboxBoolean(guard.Env(), result.get());

    mpss::utils::log_trace("Verification using standalone signature verification {}.",
                           verified ? "succeeded" : "failed");
    return verified;
}

} // namespace mpss::impl::os
