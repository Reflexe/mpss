#!/usr/bin/env bash
set -euo pipefail

preset="$1"

cmake -S . --preset "$preset"
cmake --build "out/build/$preset" --target mpss_android_test_apk

apk="$(find "out/build/$preset" tests/android -name '*.apk' | head -n 1)"
if [[ -z "$apk" ]]; then
  echo "APK not found" >&2
  find "out/build/$preset" tests/android -name '*.apk' >&2
  exit 1
fi

echo "Installing $apk"
adb install -r "$apk"

set +e
adb shell am instrument -w com.microsoft.research.mpss.tests/com.microsoft.research.mpss.tests.TestRunner > instrumentation.log
rc=$?
set -e

cat instrumentation.log
if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi
grep -q 'MPSS tests passed' instrumentation.log
if grep -Eq 'FAILURES!!!|MPSS tests failed|INSTRUMENTATION_CODE: -1' instrumentation.log; then
  exit 1
fi
