// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_keypair.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/impl/os_backend.h"
#include "mpss/utils/utilities.h"
#include <optional>

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

void GetKeyProperties(std::string_view name, bool &hardware_backed, const char **storage_description)
{
    hardware_backed = false;
    *storage_description = nullptr;

    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return;
    }
    JNIEnv *const env = guard.Env();

    jclass key_management = mpss::impl::os::JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class");
        return;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "GetKeySecurityLevel", "(Ljava/lang/String;)I");
    if (mpss::impl::os::utils::CheckAndClearException(env, "resolving KeyManagement.GetKeySecurityLevel"))
    {
        return;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetKeySecurityLevel Java method");
        return;
    }

    const std::string keyNameStr(name);
    jni_string keyName(env, env->NewStringUTF(keyNameStr.c_str()));
    if (mpss::impl::os::utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return;
    }
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String");
        return;
    }

    const jint result = env->CallStaticIntMethod(key_management, method, keyName.get());
    if (mpss::impl::os::utils::CheckAndClearException(env, "calling KeyManagement.GetKeySecurityLevel"))
    {
        return;
    }
    if (-1 == result)
    {
        mpss::impl::os::utils::ReportJavaError(env, "KeyManagement.GetKeySecurityLevel");
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

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_warning("Key name cannot be empty.");
        return nullptr;
    }

    mpss::utils::log_trace("Attempting to open key '{}' on Android backend.", name);

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return nullptr;
    }
    JNIEnv *const env = guard.Env();

    jclass key_management = JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    const std::string nameStr{name};
    jni_string keyName(env, env->NewStringUTF(nameStr.c_str()));
    if (utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return nullptr;
    }
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not create key name Java string.");
        return nullptr;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "OpenKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.OpenKey"))
    {
        return nullptr;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.OpenKey Java method.");
        return nullptr;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, keyName.get()));
    if (utils::CheckAndClearException(env, "calling KeyManagement.OpenKey"))
    {
        return nullptr;
    }
    if (result.is_null())
    {
        utils::ReportJavaError(env, "KeyManagement.OpenKey");
        return nullptr;
    }

    const std::optional<bool> opened = utils::UnboxBoolean(env, result.get());
    if (!opened.has_value())
    {
        return nullptr;
    }
    if (!opened.value())
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
        return nullptr;
    }

    // Now we need the Algorithm.
    jmethodID mid_algo = env->GetStaticMethodID(key_management, "GetKeyAlgorithm",
                                                "(Ljava/lang/String;)Lcom/microsoft/research/mpss/Algorithm;");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.GetKeyAlgorithm"))
    {
        return nullptr;
    }
    if (nullptr == mid_algo)
    {
        mpss::utils::log_and_set_error("Failed to get KeyManagement.GetKeyAlgorithm method.");
        return nullptr;
    }

    jni_object algo_result(env, env->CallStaticObjectMethod(key_management, mid_algo, keyName.get()));
    if (utils::CheckAndClearException(env, "calling KeyManagement.GetKeyAlgorithm"))
    {
        return nullptr;
    }
    if (algo_result.is_null())
    {
        utils::ReportJavaError(env, "KeyManagement.GetKeyAlgorithm");
        return nullptr;
    }

    jclass algorithm_class = JNIHelper::AlgorithmClass();
    if (nullptr == algorithm_class)
    {
        mpss::utils::log_and_set_error("Failed to get Java class for Algorithm.");
        return nullptr;
    }

    jmethodID nameMethod = env->GetMethodID(algorithm_class, "name", "()Ljava/lang/String;");
    if (utils::CheckAndClearException(env, "resolving Algorithm.name"))
    {
        return nullptr;
    }
    if (nullptr == nameMethod)
    {
        mpss::utils::log_and_set_error("Could not get method id for Algorithm.name.");
        return nullptr;
    }

    jni_string algo_name(env, reinterpret_cast<jstring>(env->CallObjectMethod(algo_result.get(), nameMethod)));
    if (utils::CheckAndClearException(env, "calling Algorithm.name"))
    {
        return nullptr;
    }
    if (algo_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not get name of enum Algorithm.");
        return nullptr;
    }

    const std::string algo_name_str = mpss::impl::os::utils::GetString(env, algo_name.get());
    if (algo_name_str.empty())
    {
        return nullptr;
    }
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
    if (unsupported == algorithm)
    {
        utils::ReportJavaError(env, "KeyManagement.GetKeyAlgorithm");
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

    // Finally, we can return the key.
    mpss::utils::log_trace("Key '{}' opened on Android with {} storage.", name, storage_description);
    return std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
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
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return nullptr;
    }
    JNIEnv *const env = guard.Env();

    jclass key_management = JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    jmethodID method = env->GetStaticMethodID(
        key_management, "CreateKey", "(Ljava/lang/String;Lcom/microsoft/research/mpss/Algorithm;)Ljava/lang/Boolean;");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.CreateKey"))
    {
        return nullptr;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CreateKey Java method.");
        return nullptr;
    }

    const std::string keyNameStr(name);
    jni_string keyName(env, env->NewStringUTF(keyNameStr.c_str()));
    if (utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return nullptr;
    }
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String.");
        return nullptr;
    }

    jclass algorithmClass = JNIHelper::AlgorithmClass();
    if (nullptr == algorithmClass)
    {
        mpss::utils::log_and_set_error("Could not get Algorithm Java class.");
        return nullptr;
    }

    jfieldID algoFieldId = nullptr;

    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        algoFieldId = env->GetStaticFieldID(algorithmClass, "secp256r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp384r1_sha384:
        algoFieldId = env->GetStaticFieldID(algorithmClass, "secp384r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp521r1_sha512:
        algoFieldId = env->GetStaticFieldID(algorithmClass, "secp521r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    default:
        mpss::utils::log_warning("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (utils::CheckAndClearException(env, "resolving an Algorithm enum value"))
    {
        return nullptr;
    }
    if (nullptr == algoFieldId)
    {
        mpss::utils::log_and_set_error("Could not find appropriate enum value for Algorithm.");
        return nullptr;
    }

    jni_object algorithmValue(env, env->GetStaticObjectField(algorithmClass, algoFieldId));
    if (utils::CheckAndClearException(env, "getting an Algorithm enum value"))
    {
        return nullptr;
    }
    if (algorithmValue.is_null())
    {
        mpss::utils::log_and_set_error("Could not get object for Algorithm value.");
        return nullptr;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, keyName.get(), algorithmValue.get()));
    if (utils::CheckAndClearException(env, "calling KeyManagement.CreateKey"))
    {
        return nullptr;
    }
    if (result.is_null())
    {
        utils::ReportJavaError(env, "KeyManagement.CreateKey");
        return nullptr;
    }

    const std::optional<bool> created = utils::UnboxBoolean(env, result.get());
    if (!created.has_value())
    {
        return nullptr;
    }
    if (!created.value())
    {
        utils::ReportJavaError(env, "KeyManagement.CreateKey");
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

    mpss::utils::log_trace("Key '{}' created on Android with {} storage.", name, storage_description);
    return std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description);
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

    // The verification algorithm is inferred from the public key length on the Java side, so require
    // an exact length match here to keep the public key bound to the requested algorithm.
    const std::size_t expected_pk_size = mpss::utils::get_public_key_size(algorithm);
    if (public_key.size() != expected_pk_size)
    {
        mpss::utils::log_warning("Public key length {} does not match algorithm '{}' (expected {}).", public_key.size(),
                                 get_algorithm_info(algorithm).type_str, expected_pk_size);
        return false;
    }

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return false;
    }
    JNIEnv *const env = guard.Env();

    jclass key_management = JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "VerifySignature", "([B[B[B)Ljava/lang/Boolean;");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature Java method.");
        return false;
    }

    jni_bytearray hash_arr(env, utils::ToJByteArray(env, hash));
    if (hash_arr.is_null())
    {
        return false;
    }

    jni_bytearray pk_arr(env, utils::ToJByteArray(env, public_key));
    if (pk_arr.is_null())
    {
        return false;
    }

    jni_bytearray sig_arr(env, utils::ToJByteArray(env, sig));
    if (sig_arr.is_null())
    {
        return false;
    }

    jni_object result(env,
                      env->CallStaticObjectMethod(key_management, method, hash_arr.get(), sig_arr.get(), pk_arr.get()));
    if (utils::CheckAndClearException(env, "calling KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (result.is_null())
    {
        utils::ReportJavaError(env, "KeyManagement.VerifySignature");
        return false;
    }

    const std::optional<bool> verified = utils::UnboxBoolean(env, result.get());
    if (!verified.has_value())
    {
        return false;
    }

    mpss::utils::log_trace("Verification using standalone signature verification {}.",
                           verified.value() ? "succeeded" : "failed");
    return verified.value();
}

} // namespace mpss::impl::os
