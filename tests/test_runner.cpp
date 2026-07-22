// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tests/test_entry.h"
#ifdef __ANDROID__
#include "mpss/impl/android/JNIHelper.h"
#include <jni.h>
#endif

#ifdef __ANDROID__
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM * /*vm*/, void * /*reserved*/)
{
    return mpss::impl::os::JNIHelper::Initialized() ? JNI_VERSION_1_6 : JNI_ERR;
}

extern "C" JNIEXPORT jint JNICALL Java_com_microsoft_research_mpss_tests_TestRunner_runAllTests(JNIEnv * /*env*/,
                                                                                                jclass /*test_runner*/)
{
    char executable_name[] = "mpss_tests";
    char *argv[] = {executable_name, nullptr};
    return mpss::tests::run_all_tests(1, argv);
}
#else
int main(int argc, char *argv[])
{
    return mpss::tests::run_all_tests(argc, argv);
}
#endif
