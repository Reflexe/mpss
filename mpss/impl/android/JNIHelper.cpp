// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/android_utils.h"

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /*reserved*/)
{
    return mpss::impl::os::JNIHelper::Init(vm) ? JNI_VERSION_1_6 : JNI_ERR;
}

extern "C" JNIEXPORT void JNI_OnUnload(JavaVM *vm, void * /*reserved*/)
{
    mpss::impl::os::JNIHelper::Uninit(vm);
}

JavaVM *mpss::impl::os::JNIHelper::java_vm_ = nullptr;
jclass mpss::impl::os::JNIHelper::key_management_class_ = nullptr;
jclass mpss::impl::os::JNIHelper::algorithm_class_ = nullptr;
jclass mpss::impl::os::JNIHelper::boolean_class_ = nullptr;
jmethodID mpss::impl::os::JNIHelper::boolean_value_method_ = nullptr;
thread_local bool mpss::impl::os::JNIEnvGuard::attached_ = false;
thread_local int mpss::impl::os::JNIEnvGuard::ref_count_ = 0;

namespace mpss::impl::os
{

bool JNIHelper::Init(JavaVM *vm)
{
    if (nullptr == vm)
    {
        return false;
    }
    if (nullptr != java_vm_)
    {
        return vm == java_vm_ && Initialized();
    }

    JNIEnv *env = nullptr;
    if (JNI_OK != vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) || nullptr == env)
    {
        return false;
    }

    java_vm_ = vm;

    const auto cache_class = [env](const char *name, jclass &destination) {
        jclass local_class = env->FindClass(name);
        if (utils::CheckAndClearException(env, name) || nullptr == local_class)
        {
            return false;
        }

        destination = reinterpret_cast<jclass>(env->NewGlobalRef(local_class));
        const bool failed = utils::CheckAndClearException(env, name) || nullptr == destination;
        env->DeleteLocalRef(local_class);
        return !failed;
    };

    if (!cache_class("com/microsoft/research/mpss/KeyManagement", key_management_class_) ||
        !cache_class("com/microsoft/research/mpss/Algorithm", algorithm_class_) ||
        !cache_class("java/lang/Boolean", boolean_class_))
    {
        Uninit(vm);
        return false;
    }

    boolean_value_method_ = env->GetMethodID(boolean_class_, "booleanValue", "()Z");
    if (utils::CheckAndClearException(env, "resolving Boolean.booleanValue") || nullptr == boolean_value_method_)
    {
        Uninit(vm);
        return false;
    }

    return true;
}

void JNIHelper::Uninit(JavaVM *vm)
{
    if (nullptr == vm || vm != java_vm_)
    {
        return;
    }

    JNIEnv *env = nullptr;
    if (JNI_OK == vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) && nullptr != env)
    {
        if (nullptr != boolean_class_)
        {
            env->DeleteGlobalRef(boolean_class_);
        }
        if (nullptr != algorithm_class_)
        {
            env->DeleteGlobalRef(algorithm_class_);
        }
        if (nullptr != key_management_class_)
        {
            env->DeleteGlobalRef(key_management_class_);
        }
    }

    boolean_value_method_ = nullptr;
    boolean_class_ = nullptr;
    algorithm_class_ = nullptr;
    key_management_class_ = nullptr;
    java_vm_ = nullptr;
}

bool JNIHelper::Initialized()
{
    return nullptr != java_vm_ && nullptr != key_management_class_ && nullptr != algorithm_class_ &&
           nullptr != boolean_class_ && nullptr != boolean_value_method_;
}

void JNIHelper::Detach()
{
    if (nullptr != java_vm_)
    {
        java_vm_->DetachCurrentThread();
    }
}

JNIEnv *JNIHelper::GetEnv(bool *did_attach)
{
    if (nullptr != did_attach)
    {
        *did_attach = false;
    }

    JNIEnv *env = nullptr;
    if (nullptr == java_vm_)
    {
        return nullptr;
    }

    const jint result = java_vm_->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (JNI_OK == result)
    {
        return env;
    }
    if (JNI_EDETACHED == result)
    {
        if (0 == java_vm_->AttachCurrentThread(&env, nullptr))
        {
            if (nullptr != did_attach)
            {
                *did_attach = true;
            }
            return env;
        }
        return nullptr;
    }
    return nullptr;
}

jclass JNIHelper::KeyManagementClass()
{
    return key_management_class_;
}

jclass JNIHelper::AlgorithmClass()
{
    return algorithm_class_;
}

jclass JNIHelper::BooleanClass()
{
    return boolean_class_;
}

jmethodID JNIHelper::BooleanValueMethod()
{
    return boolean_value_method_;
}

// RAII Wrapper.
JNIEnvGuard::JNIEnvGuard()
{
    bool attached = false;
    env_ = JNIHelper::GetEnv(&attached);
    if (nullptr == env_)
    {
        return;
    }

    ref_count_++;
    if (attached)
    {
        attached_ = true;
    }
}

JNIEnvGuard::~JNIEnvGuard()
{
    if (nullptr == env_)
    {
        return;
    }

    ref_count_--;
    if (0 == ref_count_)
    {
        if (attached_)
        {
            JNIHelper::Detach();
            attached_ = false;
        }
    }
}

} // namespace mpss::impl::os
