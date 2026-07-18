// Extract the VBS root public key (NCRYPT_VBS_ROOT_PUB_PROPERTY). If this value is
// identical across machines it is a GLOBAL, pinnable root => VBS claims are
// externally/offline verifiable. If per-machine, they are not.
#include <windows.h>
#include <ncrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "ncrypt.lib")

#ifndef NCRYPT_VBS_ROOT_PUB_PROPERTY
#define NCRYPT_VBS_ROOT_PUB_PROPERTY L"VBS_ROOT_PUB"
#endif
#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_FLAG
#define NCRYPT_USE_VIRTUAL_ISOLATION_FLAG 0x00020000
#endif

static void dumpHex(const char* label, const BYTE* p, DWORD n) {
    printf("%s (%lu bytes):\n", label, (unsigned long)n);
    for (DWORD i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

static void tryProp(NCRYPT_HANDLE h, const char* who) {
    DWORD cb = 0;
    SECURITY_STATUS st = NCryptGetProperty(h, NCRYPT_VBS_ROOT_PUB_PROPERTY, nullptr, 0, &cb, 0);
    printf("GetProperty(%s, VBS_ROOT_PUB) size: st=0x%08lx cb=%lu\n", who, (unsigned long)st, cb);
    if (st == ERROR_SUCCESS && cb > 0) {
        std::vector<BYTE> buf(cb); DWORD out = 0;
        st = NCryptGetProperty(h, NCRYPT_VBS_ROOT_PUB_PROPERTY, buf.data(), cb, &out, 0);
        if (st == ERROR_SUCCESS) dumpHex("VBS_ROOT_PUB", buf.data(), out);
    }
}

int main() {
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    printf("OpenProvider: st=0x%08lx\n", (unsigned long)st);
    if (st != ERROR_SUCCESS) return 1;

    tryProp(prov, "provider");

    const wchar_t* name = L"mpss_vbs_root_probe";
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenKey(prov, &key, name, 0, 0) == ERROR_SUCCESS) { NCryptDeleteKey(key, 0); key = 0; }
    st = NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, NCRYPT_USE_VIRTUAL_ISOLATION_FLAG);
    if (st == ERROR_SUCCESS) {
        NCryptFinalizeKey(key, 0);
        tryProp(key, "vbs-key");
        NCryptDeleteKey(key, 0);
    } else {
        printf("VBS key create failed: st=0x%08lx\n", (unsigned long)st);
    }

    NCryptFreeObject(prov);
    return 0;
}
