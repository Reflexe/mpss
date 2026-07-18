// VBS verification deep-dive: try every NCryptVerifyClaim parameterization for a
// VBS_ROOT claim, including a re-imported PUBLIC subject key (simulates a relying
// party that only holds the public key + the claim blob).
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "ncrypt.lib")

#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_FLAG
#define NCRYPT_USE_VIRTUAL_ISOLATION_FLAG 0x00020000
#endif
#ifndef NCRYPT_CLAIM_VBS_ROOT
#define NCRYPT_CLAIM_VBS_ROOT 0x00000005
#endif
#ifndef NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE
#define NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE 49
#endif
#ifndef NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG
#define NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG 0x00100000
#endif

static void verifyTry(const char* label, NCRYPT_KEY_HANDLE subj, DWORD type,
                      BYTE* claim, DWORD clen, DWORD flags, bool withOut) {
    NCryptBufferDesc outDesc{}; outDesc.ulVersion = NCRYPTBUFFER_VERSION;
    SECURITY_STATUS st = NCryptVerifyClaim(subj, 0, type, nullptr, claim, clen,
                                           withOut ? &outDesc : nullptr, flags);
    printf("  verify[%-14s]: st=0x%08lx => %s\n", label, (unsigned long)st,
           st == ERROR_SUCCESS ? "VERIFIED" : "fail");
}

int main() {
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) { printf("prov fail\n"); return 1; }
    const wchar_t* name = L"mpss_vbs_verify_probe";
    NCRYPT_KEY_HANDLE subj = 0;
    if (NCryptOpenKey(prov, &subj, name, 0, 0) == ERROR_SUCCESS) { NCryptDeleteKey(subj, 0); subj = 0; }
    if (NCryptCreatePersistedKey(prov, &subj, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, NCRYPT_USE_VIRTUAL_ISOLATION_FLAG) != ERROR_SUCCESS) { printf("vbs key create fail\n"); return 2; }
    if (NCryptFinalizeKey(subj, 0) != ERROR_SUCCESS) { printf("finalize fail\n"); return 3; }

    unsigned char nonce[32]; for (int i = 0; i < 32; ++i) nonce[i] = (unsigned char)(i + 1);
    NCryptBuffer b{}; b.cbBuffer = sizeof(nonce); b.BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE; b.pvBuffer = nonce;
    NCryptBufferDesc d{}; d.ulVersion = NCRYPTBUFFER_VERSION; d.cBuffers = 1; d.pBuffers = &b;

    DWORD cb = 0;
    if (NCryptCreateClaim(subj, 0, NCRYPT_CLAIM_VBS_ROOT, &d, nullptr, 0, &cb, 0) != ERROR_SUCCESS || cb == 0) { printf("claim size fail\n"); return 4; }
    std::vector<BYTE> claim(cb); DWORD w = 0;
    if (NCryptCreateClaim(subj, 0, NCRYPT_CLAIM_VBS_ROOT, &d, claim.data(), cb, &w, 0) != ERROR_SUCCESS) { printf("claim fill fail\n"); return 5; }
    printf("VBS_ROOT claim created: %lu bytes\n", (unsigned long)w);

    // Export subject public key and re-import as a standalone public handle.
    NCRYPT_KEY_HANDLE pubKey = 0;
    DWORD cbPub = 0;
    SECURITY_STATUS est = NCryptExportKey(subj, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &cbPub, 0);
    printf("ExportKey(pub): st=0x%08lx cb=%lu\n", (unsigned long)est, cbPub);
    if (est == ERROR_SUCCESS && cbPub > 0) {
        std::vector<BYTE> pub(cbPub);
        est = NCryptExportKey(subj, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, pub.data(), cbPub, &cbPub, 0);
        if (est == ERROR_SUCCESS) {
            est = NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, &pubKey, pub.data(), cbPub, 0);
            printf("ImportKey(pub): st=0x%08lx\n", (unsigned long)est);
        }
    }

    printf("Verify attempts (VBS_ROOT):\n");
    verifyTry("priv,flags0", subj, NCRYPT_CLAIM_VBS_ROOT, claim.data(), w, 0, false);
    verifyTry("priv,details", subj, NCRYPT_CLAIM_VBS_ROOT, claim.data(), w, NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG, true);
    if (pubKey) {
        verifyTry("pub,flags0", pubKey, NCRYPT_CLAIM_VBS_ROOT, claim.data(), w, 0, false);
        verifyTry("pub,details", pubKey, NCRYPT_CLAIM_VBS_ROOT, claim.data(), w, NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG, true);
    }
    verifyTry("null,flags0", 0, NCRYPT_CLAIM_VBS_ROOT, claim.data(), w, 0, false);
    verifyTry("null,details", 0, NCRYPT_CLAIM_VBS_ROOT, claim.data(), w, NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG, true);

    if (pubKey) NCryptFreeObject(pubKey);
    NCryptDeleteKey(subj, 0);
    NCryptFreeObject(prov);
    return 0;
}
