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

// Point the CWD and TMPDIR at an app-writable dir; the e2e test writes PEM files
// with relative paths and the instrumented app's CWD is the read-only "/".
void set_working_directory(JNIEnv *env, jstring working_dir)
{
    if (nullptr == working_dir)
    {
        return;
    }
    const char *dir = env->GetStringUTFChars(working_dir, nullptr);
    if (nullptr == dir)
    {
        return;
    }
    if (0 != chdir(dir))
    {
        __android_log_print(ANDROID_LOG_WARN, kTag, "chdir(\"%s\") failed.", dir);
    }
    setenv("TMPDIR", dir, 1);
    env->ReleaseStringUTFChars(working_dir, dir);
}
} // namespace

// Runs on the calling (instrumentation) thread so the backend's FindClass
// resolves against the app classloader.
extern "C" JNIEXPORT jint JNICALL Java_com_microsoft_research_mpss_test_NativeTests_run(JNIEnv *env, jclass,
                                                                                        jstring working_dir)
{
    set_working_directory(env, working_dir);

    int argc = 1;
    char arg0[] = "mpss_tests";
    char *argv[] = {arg0, nullptr};
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new LogcatListener);
    return RUN_ALL_TESTS();
}
