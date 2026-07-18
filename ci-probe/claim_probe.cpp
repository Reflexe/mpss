// Capability probe: does this Windows runner have a usable TPM that can produce
// a real NCryptCreateClaim attestation claim? Prints status codes; never asserts.
#include <windows.h>
#include <ncrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "ncrypt.lib")

#ifndef NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT
#define NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT 0x00000003
#endif
#ifndef NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE
#define NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE 49
#endif

int main() {
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    printf("OpenStorageProvider(Platform): st=0x%08lx\n", (unsigned long)st);
    if (st != ERROR_SUCCESS) { printf("RESULT=no_platform_provider\n"); return 0; }

    const wchar_t* keyName = L"mpss_ci_claim_probe";
    NCRYPT_KEY_HANDLE subj = 0;
    if (NCryptOpenKey(prov, &subj, keyName, 0, 0) == ERROR_SUCCESS) { NCryptDeleteKey(subj, 0); subj = 0; }

    st = NCryptCreatePersistedKey(prov, &subj, NCRYPT_ECDSA_P256_ALGORITHM, keyName, 0, 0);
    printf("CreatePersistedKey(EC P256): st=0x%08lx\n", (unsigned long)st);
    if (st != ERROR_SUCCESS) { printf("RESULT=no_tpm_key\n"); NCryptFreeObject(prov); return 0; }
    st = NCryptFinalizeKey(subj, 0);
    printf("FinalizeKey: st=0x%08lx\n", (unsigned long)st);
    if (st != ERROR_SUCCESS) { NCryptDeleteKey(subj, 0); NCryptFreeObject(prov); printf("RESULT=finalize_failed\n"); return 0; }

    unsigned char nonce[32];
    for (int i = 0; i < 32; ++i) nonce[i] = (unsigned char)(i * 7 + 1);
    NCryptBuffer buf{}; buf.cbBuffer = sizeof(nonce);
    buf.BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE; buf.pvBuffer = nonce;
    NCryptBufferDesc desc{}; desc.ulVersion = NCRYPTBUFFER_VERSION; desc.cBuffers = 1; desc.pBuffers = &buf;

    DWORD cb = 0;
    st = NCryptCreateClaim(subj, 0, NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT, &desc, nullptr, 0, &cb, 0);
    printf("CreateClaim(AUTHORITY_AND_SUBJECT): st=0x%08lx cb=%lu\n", (unsigned long)st, cb);
    if (st == ERROR_SUCCESS && cb > 0) {
        std::vector<BYTE> claim(cb); DWORD written = 0;
        st = NCryptCreateClaim(subj, 0, NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT, &desc, claim.data(), cb, &written, 0);
        printf("CreateClaim(fill): st=0x%08lx written=%lu\n", (unsigned long)st, written);
        printf("RESULT=tpm_claim_ok bytes=%lu\n", (unsigned long)written);
    } else {
        printf("RESULT=claim_failed\n");
    }

    NCryptDeleteKey(subj, 0);
    NCryptFreeObject(prov);
    return 0;
}
