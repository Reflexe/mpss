// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_keypair.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/impl/key_probe.h"
#include "mpss/impl/os_backend.h"
#include "mpss/utils/scope_guard.h"
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

std::optional<mpss::KeyInfo> get_key_properties(std::string_view name)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return std::nullopt;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class");
        return std::nullopt;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "GetKeySecurityLevel", "(Ljava/lang/String;)I");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.GetKeySecurityLevel"))
    {
        return std::nullopt;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetKeySecurityLevel Java method");
        return std::nullopt;
    }

    const std::string key_name_str(name);
    jni_string key_name(env, env->NewStringUTF(key_name_str.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return std::nullopt;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String");
        return std::nullopt;
    }

    const jint result = env->CallStaticIntMethod(key_management, method, key_name.get());
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.GetKeySecurityLevel"))
    {
        return std::nullopt;
    }
    if (-1 == result)
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.GetKeySecurityLevel");
        return std::nullopt;
    }

    std::optional<mpss::KeyInfo> key_info =
        mpss::impl::os::android_key_info_from_security_level(static_cast<std::int32_t>(result));
    if (!key_info.has_value())
    {
        mpss::utils::log_and_set_error("Unknown result from KeyManagement.GetKeySecurityLevel");
    }
    return key_info;
}

} // namespace

std::optional<mpss::KeyInfo>
mpss::impl::os::android_key_info_from_security_level(std::int32_t security_level) noexcept
{
    using enum mpss::IsolationLevel;

    switch (security_level)
    {
    case 0:
        return mpss::KeyInfo{software, unknown_storage};
    case 1:
        return mpss::KeyInfo{software, software_storage};
    case 2:
        return mpss::KeyInfo{mixed, unknown_secure_storage};
    case 3:
        return mpss::KeyInfo{mixed, trusted_storage};
    case 4:
        return mpss::KeyInfo{hardware, strongbox_storage};
    default:
        return std::nullopt;
    }
}

namespace mpss::impl::os
{

using enum Algorithm;

namespace
{

using OpenKeyResult = KeyProbeResult<std::unique_ptr<KeyPair>>;

OpenKeyResult try_open_key(std::string_view name)
{
    mpss::utils::log_trace("Attempting to open key '{}' on Android backend.", name);

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    const std::string name_str{name};
    jni_string key_name(env, env->NewStringUTF(name_str.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not create key name Java string.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jmethodID method = env->GetStaticMethodID(key_management, "OpenKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.OpenKey"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.OpenKey Java method.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, key_name.get()));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.OpenKey"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.OpenKey");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    const std::optional<bool> opened = utils::unbox_boolean(env, result.get());
    if (!opened.has_value())
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (!opened.value())
    {
        return {.status = KeyProbeStatus::not_found, .value = nullptr};
    }

    bool keep_runtime_handle = false;
    SCOPE_GUARD({
        if (!keep_runtime_handle)
        {
            static_cast<void>(close_android_key(name));
        }
    });

    const std::optional<KeyInfo> key_info = get_key_properties(name);
    if (!key_info.has_value())
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    // Now we need the Algorithm.
    jmethodID mid_algo = env->GetStaticMethodID(key_management, "GetKeyAlgorithm",
                                                "(Ljava/lang/String;)Lcom/microsoft/research/mpss/Algorithm;");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.GetKeyAlgorithm"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (nullptr == mid_algo)
    {
        mpss::utils::log_and_set_error("Failed to get KeyManagement.GetKeyAlgorithm method.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jni_object algo_result(env, env->CallStaticObjectMethod(key_management, mid_algo, key_name.get()));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.GetKeyAlgorithm"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (algo_result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.GetKeyAlgorithm");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jclass algorithm_class = JNIHelper::algorithm_class();
    if (nullptr == algorithm_class)
    {
        mpss::utils::log_and_set_error("Failed to get Java class for Algorithm.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jmethodID name_method = env->GetMethodID(algorithm_class, "name", "()Ljava/lang/String;");
    if (utils::check_and_clear_exception(env, "resolving Algorithm.name"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (nullptr == name_method)
    {
        mpss::utils::log_and_set_error("Could not get method id for Algorithm.name.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jni_string algo_name(env, reinterpret_cast<jstring>(env->CallObjectMethod(algo_result.get(), name_method)));
    if (utils::check_and_clear_exception(env, "calling Algorithm.name"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (algo_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not get name of enum Algorithm.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    const std::string algo_name_str = mpss::impl::os::utils::get_string(env, algo_name.get());
    if (algo_name_str.empty())
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
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
        utils::report_java_error(env, "KeyManagement.GetKeyAlgorithm");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    keep_runtime_handle = true;
    mpss::utils::log_trace("Key '{}' opened on Android with {} storage.", name, key_info->storage_description);
    return {.status = KeyProbeStatus::found,
            .value = std::make_unique<AndroidKeyPair>(algorithm, name, key_info->isolation_level,
                                                      key_info->storage_description)};
}

} // namespace

std::unique_ptr<KeyPair> open_key(std::string_view name, IsolationLevel minimum_isolation)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    OpenKeyResult result = try_open_key(name);
    if (KeyProbeStatus::not_found == result.status)
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
    }
    if (nullptr != result.value &&
        !mpss::meets_minimum_isolation(result.value->key_info().isolation_level, minimum_isolation))
    {
        result.value.reset();
        mpss::utils::log_and_set_error("Key '{}' does not meet the requested minimum isolation.", name);
        return nullptr;
    }

    return std::move(result.value);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy,
                                    IsolationLevel minimum_isolation)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (KeyPolicy::none != policy)
    {
        mpss::utils::log_and_set_error("Android backend does not support the requested key policy.");
        return nullptr;
    }

    // Check if the key already exists. A probe that could not determine presence must not create, or an
    // existing key could be replaced.
    OpenKeyResult existing_key = try_open_key(name);
    if (KeyProbeStatus::operational_error == existing_key.status)
    {
        return nullptr;
    }
    if (KeyProbeStatus::found == existing_key.status)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
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
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    jmethodID method = env->GetStaticMethodID(
        key_management, "CreateKey", "(Ljava/lang/String;Lcom/microsoft/research/mpss/Algorithm;Z)I");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.CreateKey"))
    {
        return nullptr;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CreateKey Java method.");
        return nullptr;
    }

    const std::string key_name_str(name);
    jni_string key_name(env, env->NewStringUTF(key_name_str.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return nullptr;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String.");
        return nullptr;
    }

    jclass algorithm_class = JNIHelper::algorithm_class();
    if (nullptr == algorithm_class)
    {
        mpss::utils::log_and_set_error("Could not get Algorithm Java class.");
        return nullptr;
    }

    jfieldID algo_field_id = nullptr;

    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        algo_field_id = env->GetStaticFieldID(algorithm_class, "secp256r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp384r1_sha384:
        algo_field_id = env->GetStaticFieldID(algorithm_class, "secp384r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp521r1_sha512:
        algo_field_id = env->GetStaticFieldID(algorithm_class, "secp521r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    default:
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (utils::check_and_clear_exception(env, "resolving an Algorithm enum value"))
    {
        return nullptr;
    }
    if (nullptr == algo_field_id)
    {
        mpss::utils::log_and_set_error("Could not find appropriate enum value for Algorithm.");
        return nullptr;
    }

    jni_object algorithm_value(env, env->GetStaticObjectField(algorithm_class, algo_field_id));
    if (utils::check_and_clear_exception(env, "getting an Algorithm enum value"))
    {
        return nullptr;
    }
    if (algorithm_value.is_null())
    {
        mpss::utils::log_and_set_error("Could not get object for Algorithm value.");
        return nullptr;
    }

    auto inspect_created_key = [&]() -> std::unique_ptr<KeyPair> {
        const std::optional<KeyInfo> key_info = get_key_properties(name);
        if (!key_info.has_value())
        {
            const std::string inspection_error = mpss::get_error();
            if (!delete_android_key(name))
            {
                const std::string cleanup_error = mpss::get_error();
                mpss::utils::log_and_set_error(
                    "Failed to inspect newly created Android key '{}' and cleanup failed: {}; inspection error: {}",
                    name, cleanup_error, inspection_error);
            }
            else
            {
                mpss::utils::set_error(inspection_error);
            }
            return nullptr;
        }

        if (!mpss::meets_minimum_isolation(key_info->isolation_level, minimum_isolation))
        {
            const IsolationLevel actual_isolation = key_info->isolation_level;
            mpss::utils::log_and_set_error(
                "Newly created Android key '{}' measured at isolation level {} below requested minimum {}.", name,
                static_cast<unsigned>(actual_isolation), static_cast<unsigned>(minimum_isolation));
            const std::string rejection_error = mpss::get_error();
            if (!delete_android_key(name))
            {
                const std::string cleanup_error = mpss::get_error();
                mpss::utils::log_and_set_error(
                    "Newly created Android key '{}' was underqualified and cleanup failed: {}; rejection error: {}",
                    name, cleanup_error, rejection_error);
            }
            return nullptr;
        }

        mpss::utils::log_trace("Key '{}' created on Android with {} storage.", name, key_info->storage_description);
        return std::make_unique<AndroidKeyPair>(algorithm, name, key_info->isolation_level,
                                                key_info->storage_description);
    };

    auto create_in_store = [&](bool use_strongbox) {
        const jint result = env->CallStaticIntMethod(key_management, method, key_name.get(), algorithm_value.get(),
                                                     use_strongbox ? JNI_TRUE : JNI_FALSE);
        if (utils::check_and_clear_exception(env, "calling KeyManagement.CreateKey"))
        {
            return AndroidCreateOutcome::operational_error;
        }

        switch (result)
        {
        case static_cast<jint>(AndroidCreateOutcome::created):
            return AndroidCreateOutcome::created;
        case static_cast<jint>(AndroidCreateOutcome::unavailable):
            mpss::utils::log_and_set_error("StrongBox is unavailable or unsupported for algorithm '{}'.",
                                           get_algorithm_info(algorithm).type_str);
            return AndroidCreateOutcome::unavailable;
        case static_cast<jint>(AndroidCreateOutcome::operational_error):
            utils::report_java_error(env, "KeyManagement.CreateKey");
            return AndroidCreateOutcome::operational_error;
        default:
            mpss::utils::log_and_set_error("KeyManagement.CreateKey returned unknown result {}.", result);
            return AndroidCreateOutcome::operational_error;
        }
    };

    AndroidCreateOutcome strongbox_outcome = AndroidCreateOutcome::not_attempted;
    if (android_strongbox_supports(algorithm))
    {
        strongbox_outcome = create_in_store(/* use_strongbox */ true);
        if (AndroidCreateOutcome::created == strongbox_outcome)
        {
            return inspect_created_key();
        }
        if (AndroidCreateOutcome::operational_error == strongbox_outcome)
        {
            return nullptr;
        }
    }
    else
    {
        mpss::utils::log_and_set_error("StrongBox does not support algorithm '{}'.",
                                       get_algorithm_info(algorithm).type_str);
    }

    if (android_should_try_normal_keystore(minimum_isolation, strongbox_outcome))
    {
        const AndroidCreateOutcome normal_outcome = create_in_store(/* use_strongbox */ false);
        if (AndroidCreateOutcome::created == normal_outcome)
        {
            return inspect_created_key();
        }
        return nullptr;
    }

    const std::string reason = mpss::get_error();
    mpss::utils::log_and_set_error("Failed to create Android key '{}' at the requested minimum isolation: {}", name,
                                   reason);
    return nullptr;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_and_set_error("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
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
        mpss::utils::log_and_set_error("Public key length {} does not match algorithm '{}' (expected {}).",
                                       public_key.size(), get_algorithm_info(algorithm).type_str, expected_pk_size);
        return false;
    }

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return false;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "VerifySignature", "([B[B[B)Ljava/lang/Boolean;");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature Java method.");
        return false;
    }

    jni_bytearray hash_arr(env, utils::to_jbyte_array(env, hash));
    if (hash_arr.is_null())
    {
        return false;
    }

    jni_bytearray pk_arr(env, utils::to_jbyte_array(env, public_key));
    if (pk_arr.is_null())
    {
        return false;
    }

    jni_bytearray sig_arr(env, utils::to_jbyte_array(env, sig));
    if (sig_arr.is_null())
    {
        return false;
    }

    jni_object result(env,
                      env->CallStaticObjectMethod(key_management, method, hash_arr.get(), sig_arr.get(), pk_arr.get()));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.VerifySignature");
        return false;
    }

    const std::optional<bool> verified = utils::unbox_boolean(env, result.get());
    if (!verified.has_value())
    {
        return false;
    }

    mpss::utils::log_trace("Verification using standalone signature verification {}.",
                           verified.value() ? "succeeded" : "failed");
    return verified.value();
}

} // namespace mpss::impl::os
