// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.research.mpss.test;

public final class NativeTests {
    static {
        System.loadLibrary("mpss_tests_jni");
    }

    private NativeTests() {
    }

    // Runs the mpss gtest suite on the calling thread; returns the
    // RUN_ALL_TESTS() code (0 = success). workingDir is an app-writable dir used
    // as CWD/TMPDIR by tests that write files.
    public static native int run(String workingDir);
}
