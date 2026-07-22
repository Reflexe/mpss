// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/android_utils.h"
#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os::utils
{

using jni_string = JNIObj<jstring>;

namespace
{

void ClearPendingException(JNIEnv *env)
{
    if (env->ExceptionCheck())
    {
        env->ExceptionClear();
    }
}

std::string GetThrowableDescription(JNIEnv *env, jthrowable throwable)
{
    jclass throwable_class = env->GetObjectClass(throwable);
    if (nullptr == throwable_class || env->ExceptionCheck())
    {
        ClearPendingException(env);
        if (nullptr != throwable_class)
        {
            env->DeleteLocalRef(throwable_class);
        }
        return {};
    }

    jmethodID to_string = env->GetMethodID(throwable_class, "toString", "()Ljava/lang/String;");
    if (nullptr == to_string || env->ExceptionCheck())
    {
        ClearPendingException(env);
        env->DeleteLocalRef(throwable_class);
        return {};
    }

    jstring description = reinterpret_cast<jstring>(env->CallObjectMethod(throwable, to_string));
    if (nullptr == description || env->ExceptionCheck())
    {
        ClearPendingException(env);
        if (nullptr != description)
        {
            env->DeleteLocalRef(description);
        }
        env->DeleteLocalRef(throwable_class);
        return {};
    }

    const char *chars = env->GetStringUTFChars(description, /* isCopy */ nullptr);
    if (nullptr == chars || env->ExceptionCheck())
    {
        ClearPendingException(env);
        env->DeleteLocalRef(description);
        env->DeleteLocalRef(throwable_class);
        return {};
    }

    std::string result{chars};
    env->ReleaseStringUTFChars(description, chars);
    env->DeleteLocalRef(description);
    env->DeleteLocalRef(throwable_class);
    return result;
}

void ReportErrorRetrievalFailure(std::string_view operation)
{
    const std::string retrieval_error = mpss::utils::get_error();
    mpss::utils::log_and_set_error("{} failed; {}", operation, retrieval_error);
}

} // namespace

bool CheckAndClearException(JNIEnv *env, std::string_view operation)
{
    if (nullptr == env)
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable while {}.", operation);
        return true;
    }
    if (!env->ExceptionCheck())
    {
        return false;
    }

    jthrowable throwable = env->ExceptionOccurred();
    env->ExceptionClear();

    const std::string description = nullptr == throwable ? std::string{} : GetThrowableDescription(env, throwable);
    if (nullptr != throwable)
    {
        env->DeleteLocalRef(throwable);
    }

    if (description.empty())
    {
        mpss::utils::log_and_set_error("Java exception while {}.", operation);
    }
    else
    {
        mpss::utils::log_and_set_error("Java exception while {}: {}", operation, description);
    }
    return true;
}

jbyteArray ToJByteArray(JNIEnv *env, std::span<const std::byte> bytes)
{
    if (nullptr == env)
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return nullptr;
    }

    jbyteArray array = env->NewByteArray(bytes.size());
    if (CheckAndClearException(env, "allocating a Java byte array"))
    {
        return nullptr;
    }
    if (nullptr == array)
    {
        mpss::utils::log_and_set_error("Could not allocate a Java byte array.");
        return nullptr;
    }

    env->SetByteArrayRegion(array,
                            /* start */ 0, bytes.size(), reinterpret_cast<const jbyte *>(bytes.data()));
    if (CheckAndClearException(env, "copying bytes into a Java array"))
    {
        env->DeleteLocalRef(array);
        return nullptr;
    }

    return array;
}

// NOLINTNEXTLINE(readability-non-const-parameter) - JNI requires non-const JNIEnv.
std::size_t CopyJByteArrayToSpan(JNIEnv *env, jbyteArray array, std::span<std::byte> output)
{
    if (nullptr == env || nullptr == array)
    {
        mpss::utils::log_and_set_error("Cannot copy from an unavailable Java byte array.");
        return 0;
    }

    const jsize len = env->GetArrayLength(array);
    if (CheckAndClearException(env, "getting a Java byte array length"))
    {
        return 0;
    }
    if (output.size() < len)
    {
        mpss::utils::log_and_set_error("Output size is {} (expected {}).", output.size(), len);
        return 0;
    }

    env->GetByteArrayRegion(array,
                            /* start */ 0, len, reinterpret_cast<jbyte *>(output.data()));
    if (CheckAndClearException(env, "copying bytes from a Java array"))
    {
        return 0;
    }

    return len;
}

std::optional<bool> UnboxBoolean(JNIEnv *env, jobject booleanObj)
{
    if (nullptr == env || nullptr == booleanObj)
    {
        mpss::utils::log_and_set_error("Cannot unbox an unavailable Java Boolean.");
        return std::nullopt;
    }

    jclass boolean_class = JNIHelper::BooleanClass();
    jmethodID method = JNIHelper::BooleanValueMethod();
    if (nullptr == boolean_class || nullptr == method)
    {
        mpss::utils::log_and_set_error("Java Boolean metadata is unavailable.");
        return std::nullopt;
    }

    const jboolean result = env->CallBooleanMethod(booleanObj, method);
    if (CheckAndClearException(env, "unboxing a Java Boolean"))
    {
        return std::nullopt;
    }

    return JNI_TRUE == result;
}

// NOLINTNEXTLINE(readability-non-const-parameter) - JNI requires non-const JNIEnv.
void ReportJavaError(JNIEnv *env, std::string_view operation)
{
    if (nullptr == env)
    {
        mpss::utils::log_and_set_error("{} failed because the Android JNI environment is unavailable.", operation);
        return;
    }

    jclass key_management = JNIHelper::KeyManagementClass();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("{} failed; KeyManagement Java class is unavailable.", operation);
        return;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "TakeError", "()Ljava/lang/String;");
    if (CheckAndClearException(env, "resolving KeyManagement.TakeError"))
    {
        ReportErrorRetrievalFailure(operation);
        return;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("{} failed; KeyManagement.TakeError is unavailable.", operation);
        return;
    }

    jni_string error(env, reinterpret_cast<jstring>(env->CallStaticObjectMethod(key_management, method)));
    if (CheckAndClearException(env, "calling KeyManagement.TakeError"))
    {
        ReportErrorRetrievalFailure(operation);
        return;
    }
    if (error.is_null())
    {
        mpss::utils::log_and_set_error("{} failed; KeyManagement.TakeError returned null.", operation);
        return;
    }

    const char *chars = env->GetStringUTFChars(error.get(), /* isCopy */ nullptr);
    if (CheckAndClearException(env, "reading the KeyManagement error"))
    {
        ReportErrorRetrievalFailure(operation);
        return;
    }
    if (nullptr == chars)
    {
        mpss::utils::log_and_set_error("{} failed; could not read the KeyManagement error.", operation);
        return;
    }

    std::string detail{chars};
    env->ReleaseStringUTFChars(error.get(), chars);

    if (detail.empty())
    {
        mpss::utils::log_and_set_error("{} failed without Java error detail.", operation);
    }
    else
    {
        mpss::utils::log_and_set_error("{} failed: {}", operation, detail);
    }
}

// NOLINTNEXTLINE(readability-non-const-parameter) - JNI requires non-const JNIEnv.
std::string GetString(JNIEnv *env, jstring str)
{
    if (nullptr == env)
    {
        mpss::utils::log_and_set_error("env is null.");
        return {};
    }

    if (nullptr == str)
    {
        mpss::utils::log_and_set_error("Java string is null.");
        return {};
    }

    const char *chars = env->GetStringUTFChars(str, /* isCopy */ nullptr);
    if (CheckAndClearException(env, "reading a Java string"))
    {
        return {};
    }
    if (nullptr == chars)
    {
        mpss::utils::log_and_set_error("Could not read a Java string.");
        return {};
    }

    std::string result(chars);
    env->ReleaseStringUTFChars(str, chars);

    return result;
}

} // namespace mpss::impl::os::utils
