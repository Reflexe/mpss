// VBS probe: can this machine create a VBS-isolated (Key Guard) key AND produce a
// VBS attestation claim? Prints raw status codes; asserts nothing.
#include <windows.h>
#include <ncrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "ncrypt.lib")

#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_FLAG
#define NCRYPT_USE_VIRTUAL_ISOLATION_FLAG 0x00020000
#endif
#ifndef NCRYPT_PREFER_VIRTUAL_ISOLATION_FLAG
#define NCRYPT_PREFER_VIRTUAL_ISOLATION_FLAG 0x00010000
#endif
#ifndef NCRYPT_CLAIM_VBS_ROOT
#define NCRYPT_CLAIM_VBS_ROOT 0x00000005
#endif
#ifndef NCRYPT_CLAIM_VBS_KEY_ATTESTATION_STATEMENT
#define NCRYPT_CLAIM_VBS_KEY_ATTESTATION_STATEMENT 0x00000004
#endif
#ifndef NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE
#define NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE 49
#endif

static void tryClaim(NCRYPT_KEY_HANDLE k, DWORD type, const char* label) {
    unsigned char nonce[32];
    for (int i = 0; i < 32; ++i) nonce[i] = (unsigned char)(i + 1);
    NCryptBuffer b{}; b.cbBuffer = sizeof(nonce);
    b.BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE; b.pvBuffer = nonce;
    NCryptBufferDesc d{}; d.ulVersion = NCRYPTBUFFER_VERSION; d.cBuffers = 1; d.pBuffers = &b;

    DWORD cb = 0;
    SECURITY_STATUS st = NCryptCreateClaim(k, 0, type, &d, nullptr, 0, &cb, 0);
    printf("[%s] CreateClaim(size): st=0x%08lx cb=%lu\n", label, (unsigned long)st, cb);
    if (st == ERROR_SUCCESS && cb > 0) {
        std::vector<BYTE> c(cb); DWORD w = 0;
        st = NCryptCreateClaim(k, 0, type, &d, c.data(), cb, &w, 0);
        printf("[%s] CreateClaim(fill): st=0x%08lx written=%lu => %s\n", label,
               (unsigned long)st, w, st == ERROR_SUCCESS ? "VBS CLAIM OK" : "fail");
    }
}

static NCRYPT_KEY_HANDLE makeKey(NCRYPT_PROV_HANDLE prov, const wchar_t* name, DWORD flag, const char* label) {
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenKey(prov, &key, name, 0, 0) == ERROR_SUCCESS) { NCryptDeleteKey(key, 0); key = 0; }
    SECURITY_STATUS st = NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, flag);
    printf("CreatePersistedKey(%s): st=0x%08lx => %s\n", label, (unsigned long)st,
           st == ERROR_SUCCESS ? "KEY CREATED" : "FAILED");
    if (st != ERROR_SUCCESS) return 0;
    st = NCryptFinalizeKey(key, 0);
    printf("FinalizeKey(%s): st=0x%08lx\n", label, (unsigned long)st);
    if (st != ERROR_SUCCESS) { NCryptDeleteKey(key, 0); return 0; }
    return key;
}

int main() {
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    printf("OpenStorageProvider(Software KSP): st=0x%08lx\n", (unsigned long)st);
    if (st != ERROR_SUCCESS) return 1;

    NCRYPT_KEY_HANDLE key = makeKey(prov, L"mpss_vbs_require", NCRYPT_USE_VIRTUAL_ISOLATION_FLAG, "REQUIRE_VBS");
    if (key == 0) {
        printf("-> REQUIRE_VBS failed; trying PREFER_VBS (may fall back to software)\n");
        key = makeKey(prov, L"mpss_vbs_prefer", NCRYPT_PREFER_VIRTUAL_ISOLATION_FLAG, "PREFER_VBS");
    }
    if (key == 0) { printf("RESULT=no_vbs_key\n"); NCryptFreeObject(prov); return 0; }

    tryClaim(key, NCRYPT_CLAIM_VBS_ROOT, "VBS_ROOT(0x5)");
    tryClaim(key, NCRYPT_CLAIM_VBS_KEY_ATTESTATION_STATEMENT, "VBS_LEGACY(0x4)");

    NCryptDeleteKey(key, 0);
    NCryptFreeObject(prov);
    return 0;
}
