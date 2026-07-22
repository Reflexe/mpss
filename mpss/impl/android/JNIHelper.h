// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <jni.h>

namespace mpss::impl::os
{

class JNIHelper
{
  public:
    static bool Init(JavaVM *vm);
    static void Uninit(JavaVM *vm);
    [[nodiscard]] static bool Initialized();
    static void Detach();
    static JNIEnv *GetEnv(bool *did_attach = nullptr);
    static jclass KeyManagementClass();
    static jclass AlgorithmClass();
    static jclass BooleanClass();
    static jmethodID BooleanValueMethod();

  private:
    static JavaVM *java_vm_;
    static jclass key_management_class_;
    static jclass algorithm_class_;
    static jclass boolean_class_;
    static jmethodID boolean_value_method_;
};

// RAII Wrapper
class JNIEnvGuard
{
  public:
    JNIEnvGuard();
    virtual ~JNIEnvGuard();

    JNIEnvGuard(const JNIEnvGuard &) = delete;
    JNIEnvGuard &operator=(const JNIEnvGuard &) = delete;
    JNIEnvGuard(JNIEnvGuard &&) = delete;
    JNIEnvGuard &operator=(JNIEnvGuard &&) = delete;

    JNIEnv *operator->()
    {
        return env_;
    }

    [[nodiscard]]
    bool valid() const
    {
        return nullptr != env_;
    }

    [[nodiscard]]
    JNIEnv *Env() const
    {
        return env_;
    }

  private:
    JNIEnv *env_ = nullptr;

    static thread_local bool attached_;
    static thread_local int ref_count_;
};

} // namespace mpss::impl::os
