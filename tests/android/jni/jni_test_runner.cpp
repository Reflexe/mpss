// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <android/log.h>
#include <gtest/gtest.h>
#include <jni.h>

#include <cstdlib>
#include <unistd.h>

namespace
{
constexpr const char *kTag = "MpssTests";

// Mirror gtest results into logcat; an app process' stdout is not visible there.
class LogcatListener : public ::testing::EmptyTestEventListener
{
    void OnTestStart(const ::testing::TestInfo &info) override
    {
        __android_log_print(ANDROID_LOG_INFO, kTag, "[ RUN      ] %s.%s", info.test_suite_name(), info.name());
    }

    void OnTestPartResult(const ::testing::TestPartResult &r) override
    {
        if (!r.passed())
        {
            __android_log_print(ANDROID_LOG_ERROR, kTag, "%s:%d\n%s", r.file_name() ? r.file_name() : "?",
                                r.line_number(), r.message());
        }
    }

    void OnTestEnd(const ::testing::TestInfo &info) override
    {
        const ::testing::TestResult *r = info.result();
        const char *s = r->Skipped() ? "SKIPPED" : (r->Failed() ? "FAILED" : "OK");
        __android_log_print(r->Failed() ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, kTag, "[ %-8s ] %s.%s", s,
                            info.test_suite_name(), info.name());
    }

    void OnTestProgramEnd(const ::testing::UnitTest &u) override
    {
        __android_log_print(u.Failed() ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, kTag,
                            "Summary: %d passed, %d failed, %d skipped.", u.successful_test_count(),
                            u.failed_test_count(), u.skipped_test_count());
    }
};
} // namespace

// The Keystore backend binds its JavaVM in JNI_OnLoad and reaches Java via
// FindClass, which resolves against the caller's classloader - so the suite must
// run on this (instrumentation) thread. working_dir is an app-writable directory
// used as CWD/TMPDIR because the e2e test writes files with relative paths.
extern "C" JNIEXPORT jint JNICALL Java_com_microsoft_research_mpss_test_NativeTests_run(JNIEnv *env, jclass,
                                                                                        jstring working_dir)
{
    if (nullptr != working_dir)
    {
        const char *dir = env->GetStringUTFChars(working_dir, nullptr);
        if (nullptr != dir)
        {
            if (0 != chdir(dir))
            {
                __android_log_print(ANDROID_LOG_WARN, kTag, "chdir(\"%s\") failed.", dir);
            }
            setenv("TMPDIR", dir, 1);
            env->ReleaseStringUTFChars(working_dir, dir);
        }
    }

    int argc = 1;
    char arg0[] = "mpss_tests";
    char *argv[] = {arg0, nullptr};
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new LogcatListener);
    return RUN_ALL_TESTS();
}
