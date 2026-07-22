// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/android_keypair.h"
#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

using jni_string = utils::JNIObj<jstring>;
using jni_object = utils::JNIObj<jobject>;
using jni_bytearray = utils::JNIObj<jbyteArray>;

bool AndroidKeyPair::delete_key()
{
    mpss::utils::log_trace("Deleting Android key '{}'.", key_name_);

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

    jmethodID method = env->GetStaticMethodID(key_management, "DeleteKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.DeleteKey"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.DeleteKey Java method.");
        return false;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return false;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return false;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, key_name.get()));
    if (utils::CheckAndClearException(env, "calling KeyManagement.DeleteKey"))
    {
        return false;
    }
    if (result.is_null())
    {
        utils::ReportJavaError(env, "KeyManagement.DeleteKey");
        return false;
    }

    const std::optional<bool> deleted = utils::UnboxBoolean(env, result.get());
    if (!deleted.has_value())
    {
        return false;
    }
    if (!deleted.value())
    {
        utils::ReportJavaError(env, "KeyManagement.DeleteKey");
        return false;
    }

    mpss::utils::log_trace("Android key '{}' deleted.", key_name_);
    return true;
}

std::size_t AndroidKeyPair::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    if (sig.empty())
    {
        // If the signature buffer is empty, we want to return the size of the signature.
        return mpss::utils::get_max_signature_size(algorithm());
    }

    mpss::utils::log_trace("Signing hash with Android key '{}', hash size {}.", key_name_, hash.size());

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return 0;
    }
    if (!mpss::utils::check_sufficient_signature_buffer_size(sig, algorithm()))
    {
        return 0;
    }

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return 0;
    }
    JNIEnv *const env = guard.Env();

    jclass key_management = JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return 0;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "SignHash", "(Ljava/lang/String;[B)[B");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.SignHash"))
    {
        return 0;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.SignHash method.");
        return 0;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return 0;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return 0;
    }

    jni_bytearray hash_arr(env, utils::ToJByteArray(env, hash));
    if (hash_arr.is_null())
    {
        return 0;
    }

    jni_bytearray result(env, reinterpret_cast<jbyteArray>(
                                  env->CallStaticObjectMethod(key_management, method, key_name.get(), hash_arr.get())));
    if (utils::CheckAndClearException(env, "calling KeyManagement.SignHash"))
    {
        return 0;
    }
    if (result.is_null())
    {
        utils::ReportJavaError(env, "KeyManagement.SignHash");
        return 0;
    }

    std::size_t sig_size = utils::CopyJByteArrayToSpan(env, result.get(), sig);
    if (0 != sig_size)
    {
        mpss::utils::log_trace("Android sign produced {} byte signature.", sig_size);
    }

    return sig_size;
}

bool AndroidKeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    if (hash.empty() || sig.empty())
    {
        mpss::utils::log_warning("Nothing to verify.");
        return false;
    }

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
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

    jmethodID method =
        env->GetStaticMethodID(key_management, "VerifySignature", "(Ljava/lang/String;[B[B)Ljava/lang/Boolean;");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature method.");
        return false;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return false;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return false;
    }

    jni_bytearray hash_arr(env, utils::ToJByteArray(env, hash));
    if (hash_arr.is_null())
    {
        return false;
    }

    jni_bytearray sig_arr(env, utils::ToJByteArray(env, sig));
    if (sig_arr.is_null())
    {
        return false;
    }

    jni_object result(
        env, env->CallStaticObjectMethod(key_management, method, key_name.get(), hash_arr.get(), sig_arr.get()));
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

    // This should not fail at this point unless the signature is invalid. The caller already validated inputs.
    return verified.value();
}

std::size_t AndroidKeyPair::extract_key(std::span<std::byte> public_key) const
{
    if (public_key.empty())
    {
        return mpss::utils::get_public_key_size(algorithm());
    }
    else if (!mpss::utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }

    mpss::utils::log_trace("Extracting public key from Android key '{}'.", key_name_);

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return 0;
    }
    JNIEnv *const env = guard.Env();

    jclass key_management = JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return 0;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "GetPublicKey", "(Ljava/lang/String;)[B");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.GetPublicKey"))
    {
        return 0;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetPublicKey method.");
        return 0;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return 0;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return 0;
    }

    jni_bytearray result(
        env, reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(key_management, method, key_name.get())));
    if (utils::CheckAndClearException(env, "calling KeyManagement.GetPublicKey"))
    {
        return 0;
    }
    if (result.is_null())
    {
        utils::ReportJavaError(env, "KeyManagement.GetPublicKey");
        return 0;
    }

    std::size_t key_size = utils::CopyJByteArrayToSpan(env, result.get(), public_key);
    return key_size;
}

void AndroidKeyPair::release_key() noexcept
{
    close_key();
}

void AndroidKeyPair::close_key()
{
    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return;
    }
    JNIEnv *const env = guard.Env();

    jclass key_management = JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "CloseKey", "(Ljava/lang/String;)V");
    if (utils::CheckAndClearException(env, "resolving KeyManagement.CloseKey"))
    {
        return;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CloseKey method.");
        return;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::CheckAndClearException(env, "converting an Android key name to a Java string"))
    {
        return;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return;
    }

    env->CallStaticVoidMethod(key_management, method, key_name.get());
    static_cast<void>(utils::CheckAndClearException(env, "calling KeyManagement.CloseKey"));
}

} // namespace mpss::impl::os
