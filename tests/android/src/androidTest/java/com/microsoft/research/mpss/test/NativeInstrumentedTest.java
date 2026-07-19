// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.research.mpss.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import android.content.Context;
import java.io.File;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class NativeInstrumentedTest {
    // Scenario: Run the entire mpss gtest suite inside an instrumented app so the
    //           real Android Keystore backend is initialized through JNI_OnLoad and
    //           the backend's env->FindClass resolves against the app classloader.
    // Expected behavior: RUN_ALL_TESTS() returns 0 - every executed gtest case,
    //                    including the Keystore-backed key and end-to-end tests,
    //                    passes.
    @Test
    public void nativeGtestSuitePasses() {
        Context context = ApplicationProvider.getApplicationContext();
        File cacheDir = context.getCacheDir();
        assertNotNull("App cache dir is unavailable; cannot supply a working directory.", cacheDir);
        assertEquals(0, NativeTests.run(cacheDir.getAbsolutePath()));
    }
}
