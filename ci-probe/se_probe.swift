// Capability probe: does this environment support App Attest and Secure Enclave keys?
// Shared by the macOS-native and iOS-Simulator probe jobs.
import Foundation
import Security
#if canImport(DeviceCheck)
import DeviceCheck
#endif

func probeAppAttest() {
#if canImport(DeviceCheck)
    if #available(macOS 11.0, iOS 14.0, tvOS 15.0, *) {
        print("APPATTEST_ISSUPPORTED=\(DCAppAttestService.shared.isSupported)")
    } else {
        print("APPATTEST_ISSUPPORTED=unavailable_os")
    }
#else
    print("APPATTEST_ISSUPPORTED=no_devicecheck")
#endif
}

func probeSecureEnclave() {
    var acErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage, &acErr) else {
        print("SE_KEY_CREATE=FAILED_access_control")
        return
    }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false,
            kSecAttrAccessControl as String: access,
        ],
    ]
    var keyErr: Unmanaged<CFError>?
    if SecKeyCreateRandomKey(attrs as CFDictionary, &keyErr) != nil {
        print("SE_KEY_CREATE=SUCCESS")
    } else {
        let msg = keyErr?.takeRetainedValue().localizedDescription ?? "unknown"
        print("SE_KEY_CREATE=FAILED: \(msg)")
    }
}

print("=== MPSS SE/AppAttest probe ===")
#if targetEnvironment(simulator)
print("ENV=ios_simulator")
#elseif os(iOS)
print("ENV=ios_device")
#elseif os(macOS)
print("ENV=macos")
#else
print("ENV=other")
#endif
probeAppAttest()
probeSecureEnclave()
