#!/usr/bin/env bash
# macOS enrollment + device-attestation capability probe. Gathers hard signals
# about whether this (virtual) Mac runner could ever do ACME device attestation.
set +e

echo "=== OS version ==="
sw_vers

echo "=== MDM enrollment status ==="
profiles status -type enrollment 2>&1
sudo profiles status -type enrollment 2>&1

echo "=== Hardware / device-identity indicators ==="
system_profiler SPHardwareDataType 2>&1 | grep -Ei 'model|serial|hardware uuid|provisioning udid|activation|chip' || true

echo "=== SEP present in ioreg? ==="
ioreg -rd1 -c AppleSEPManager 2>&1 | head -n 8 || true
ioreg -l 2>/dev/null | grep -i 'sep\|secure enclave' | head -n 5 || echo "(no SEP node matched)"

echo "=== remotectl (device identity service) ==="
if command -v remotectl >/dev/null 2>&1; then
  remotectl status 2>&1 | head -n 40
else
  echo "(no remotectl)"
fi

echo "=== Can a benign config profile be installed HEADLESSLY? ==="
cat > /tmp/mpss_benign.mobileconfig <<'PROF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.reflexe.mpss.probe</string>
  <key>PayloadUUID</key><string>11111111-1111-1111-1111-111111111111</string>
  <key>PayloadDisplayName</key><string>MPSS Probe</string>
  <key>PayloadContent</key><array/>
</dict></plist>
PROF
sudo profiles install -type configuration -path /tmp/mpss_benign.mobileconfig 2>&1
echo "profiles install exit=$?"
echo "--- installed profiles ---"
profiles list 2>&1 | head -n 20
sudo profiles remove -identifier com.reflexe.mpss.probe 2>&1 || true

echo "=== DeviceCheck / AppAttest presence (framework) ==="
ls /System/Library/Frameworks/DeviceCheck.framework 2>&1 | head -n 3 || echo "(no DeviceCheck framework)"

echo "=== done ==="
