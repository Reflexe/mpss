# Design: Real Hardware Key Attestation for MPSS (Windows, macOS, iOS, Android)

Status: **Draft — key decisions resolved 2026-07-19 (§10)** · Supersedes the mock attestation in PR #1

> Every platform capability below was **verified firsthand** — either by primary-source
> research (cited in §12) or by **running probes on real hardware and on the actual CI
> runners** (§3). Nothing here is assumed. Where a fact could not be confirmed it is
> marked **UNVERIFIED**.

---

## 1. TL;DR

Real, externally-verifiable hardware **key** attestation means: the nonce↔key binding
is inside evidence signed by a **published vendor root** that any relying party can
verify offline. Measured against that bar:

| Platform / variant | Real key attestation? | Externally verifiable? (published root) | Hosted-CI E2E |
|---|---|---|---|
| **Android** TEE / StrongBox | ✅ Key Attestation (X.509 + ext) | ✅ Google HW root | ❌ emulator = software only → device farm / offline replay |
| **Android** software (emulator) | ✗ (public root, not secure) | ✗ | ✅ (structural / parser tests only) |
| **Windows TPM** | ✅ `NCryptCreateClaim` (AIK+EK) | ✅ published mfr roots (`TrustedTpm.cab`) | ❌ no TPM on runner → self-hosted / vTPM lane |
| **Windows VBS / Key Guard** | ⚠️ generation only | ❌ IDKS root is **per-machine/per-boot**, unpublished | ✅ **full generate→verify E2E** (measured) |
| **Apple** — ACME Managed Device Attestation | ✅ (managed devices, physical Apple Silicon) | ✅ Apple Enterprise Attestation Root | ❌ nothing works on hosted/VM |
| **Apple** — App Attest | ✗ **out of scope** — attests the app, not the key | — | — |

**Consequences that shape the whole design:**
1. **Apple has no API to attest an arbitrary key.** The only real hardware **key**
   attestation on Apple is **ACME** (managed devices only). App Attest is a different
   guarantee (app integrity) and must not be presented as key attestation.
2. **No hardware attestation *generates* on hosted CI except Windows VBS.** But VBS is
   not externally verifiable, so it's a **CI test lane**, not production trust.
3. **Production-verifiable lanes need real hardware**: TPM (self-hosted/vTPM), Android
   device farm, physical enrolled Mac — plus **offline replay of captured vectors** on
   every PR.

---

## 2. Goals / non-goals

**Goals**
- Produce **real, nonce-bound** hardware key-attestation evidence at key creation on
  each platform's genuine mechanism.
- A **shared, platform-agnostic verifier** that validates evidence against the correct
  **published vendor roots**, checks nonce freshness, and enforces replay/expiry.
- **Verification exercised E2E in CI** via captured-vector replay (every PR) + the VBS
  on-runner lane, with real-hardware *generation* on periodic self-hosted/device lanes.

**Non-goals**
- A production CA/PKI (we define the verification contract; the issuer is mocked).
- On-device verification (attestation is verified off-device by a relying party).
- ID attestation, App Attest anti-fraud, remote-provisioning backends.

---

## 3. Measured evidence (firsthand, 2026-07-18/19)

Probes run on the dev/build machine and on GitHub-hosted runners via a throwaway
`ci-probe/` workflow (removed after capture).

### Windows
| Probe | Dev box (has TPM + VBS) | Hosted `windows-latest` |
|---|---|---|
| TPM present | yes (Platform Crypto Provider usable) | **No** (`TpmPresent=False`; provider "device not ready") |
| TPM key + `NCryptCreateClaim` (EC P-256, AUTHORITY_AND_SUBJECT) | ✅ **1703-byte** claim | ❌ (no TPM) |
| VBS running | yes (`VBS status=2`) | **yes** (`VBS status=2`, **no TPM**) |
| VBS key + claim (`VBS_ROOT` 0x5 / legacy 0x4) | ✅ **1787-byte** claim | ✅ **1787-byte** claim |
| VBS generate→verify (`NCryptVerifyClaim`) | ✅ VERIFIED (incl. re-imported public key) | ✅ **VERIFIED** (full E2E, no TPM) |
| `VBS_ROOT_PUB` (IDKS) RSA-2048 modulus | `bd62772e…` (stable within boot) | run#1 `c338c088…`, run#2 `c1aee4cc…` |

- **`NCryptVerifyClaim` correct usage** (the earlier `NTE_INVALID_PARAMETER` was a
  call error): subject = an **imported public key handle**, `hAuthorityKey=NULL`,
  `pParameterList=NULL`, and `NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG` + non-NULL output.
- **IDKS is per-machine/per-boot** — three environments produced three different roots,
  and **two same-image `windows-latest` VMs differed**, ruling out a global/per-build
  key. Confirmed by research: no published IDKS PKI, Azure Attestation won't verify raw
  `VRCH` blobs, no OSS verifier, RSA-PSS/SHA-256, format only partly documented in
  `ncrypt.h`. → **VBS is not externally verifiable.**

### Apple (hosted `macos-latest` = Apple **Virtual** M1, macOS 26.4)
| Probe | Result |
|---|---|
| MDM enrollment | **No** (`Enrolled via DEP: No`, `MDM enrollment: No`; not in ABM) |
| Headless profile install | **Fails** — `profiles tool no longer supports installs` (macOS 11+) |
| App Attest `isSupported` (macOS) | **false** |
| App Attest `isSupported` (iOS **Simulator**) | **false** |
| Secure-Enclave key create (macOS + iOS Simulator) | **SUCCESS** — even on the Simulator ⇒ "I made an SE key" is **not** externally provable |
| `remotectl` device identity | absent |

- **ACME needs a physical Apple-Silicon SEP** — Apple's attestation servers refuse VMs
  (virtual SEP stub). Hosted/VM runners ⇒ **NO** ACME. Real lane = a **persistent,
  physical, MDM-enrolled** Mac + ACME CA (e.g. `nanoca`) verifying Apple's Enterprise
  Attestation Root. AWS EC2 Mac bare-metal = **UNVERIFIED** (ABM chain-of-custody).

### Android
Not re-probed here; from primary research: emulator ⇒ `SecurityLevel=Software` (public
root, not secure); TEE/StrongBox ⇒ real device only; verify vs Google HW root; official
verifier `android/keyattestation` has an injectable clock for offline replay.

---

## 4. The core constraints

1. **Verifiability = a published, stable, universal root.** TPM (mfr roots), Android
   (Google root), Apple ACME/App Attest (Apple roots) all qualify. **VBS does not**
   (per-machine/per-boot IDKS). "Convenient" options (VBS, App Attest) don't deliver
   externally-verifiable key provenance.
2. **Apple can't attest an arbitrary key.** No `SecKeyAttestKey`. On Apple, "attested
   key creation" means the key is created *inside* the ACME flow, not `MPSS_SE_CreateKey`.
3. **Hosted CI has no real hardware** except Windows VBS (generation). So "E2E in CI" =
   verification pipeline against **captured real vectors** + the VBS on-runner lane;
   real-hardware generation runs on periodic self-hosted/device lanes.

---

## 5. Threat model — what attestation proves

A relying party issuing a cert for public key `K` wants proof that (1) `K`'s private half
was generated in and is non-exportable from genuine secure hardware at the claimed level,
(2) the evidence is **fresh** (bound to *this* nonce), and (3) the attested key == `K`.

**Where the nonce lives (verified):**
| Platform | Nonce binding site | Signed by |
|---|---|---|
| Android | `attestationChallenge` in leaf-cert `KeyDescription` ext `1.3.6.1.4.1.11129.2.1.17` | device key → Google root |
| Apple App Attest | `SHA256(authData‖clientDataHash)` in credCert ext `1.2.840.113635.100.8.2` | Apple App Attest CA |
| Apple ACME | `SHA256(ACME token)` in a leaf-cert OID | Apple attestation CA |
| Windows TPM | `NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE` (49) in the claim | TPM AIK → EK → mfr root |
| Windows VBS | nonce in `VRCH` report | per-boot IDKS (**unanchored w/o TPM**) |

PR #1's sin: it put the nonce↔key binding in an **unsigned app-defined blob**. This
design removes that entirely — the binding always lives in vendor-signed evidence.

---

## 6. Architecture

### 6.1 Evidence contract (replaces the homemade statement)
```cpp
enum class AttestationFormat {
    none,
    android_key_attestation,      // X.509 chain, ext 1.3.6.1.4.1.11129.2.1.17
    apple_acme_managed_device,    // X.509 chain (ACME device-attest-01) — the ONLY Apple path
    windows_tpm_claim,            // NCryptCreateClaim AUTHORITY_AND_SUBJECT / PLATFORM
    windows_vbs_claim             // NCryptCreateClaim VBS_ROOT / VBS_IDENTITY — NOT real attestation
};

// Assurance is surfaced to the relying party so a caller can NEVER mistake VBS for
// externally-verifiable hardware attestation. Distinct from AttestationFormat.
enum class AttestationAssurance {
    none,
    hardware_root_verified,  // chained to a PUBLISHED vendor root: Android TEE/StrongBox, Windows TPM, Apple ACME
    vbs_self_asserted,       // Windows VBS/Key Guard: key PROTECTION only; per-boot root, NOT a provenance proof
    software                 // emulator/simulator software attestation: no hardware guarantee
};

struct AttestationEvidence {
    AttestationFormat format{AttestationFormat::none};
    std::vector<std::vector<std::byte>> cert_chain;  // DER X.509: Android, ACME
    std::vector<std::byte> blob;                     // NCrypt claim (Windows). Apple App Attest is out of scope.
    AttestationSecurityLevel security_level{AttestationSecurityLevel::unknown};
};
```
- No app-defined framing; the nonce/public key are read from the *signed* structure.
- The verifier fills `security_level` and `AttestationAssurance` from the parsed evidence.
- **`windows_vbs_claim` is a first-class, distinct format** — never folded into the TPM
  format — so both the producer and the relying party always see "this is VBS."

### 6.2 Capability-scoped API
Keep the named-key `Create(..., attestation)` for **Android/Windows** (which attest a
named key). Add an honest capability query:
```cpp
enum class AttestationCapability { none, key_attestation, app_instance, device_identity };
[[nodiscard]] static AttestationCapability attestation_capability(std::string_view backend = "os");
```
- Android/Windows → `key_attestation`.
- **Apple → `device_identity` (ACME) only.** App Attest is out of scope (it attests the
  app, not the key). `Create(..., attestation)` on Apple returns a capability error unless
  a managed-device ACME path is configured; **unmanaged Apple devices are unsupported** for
  key attestation.
- Fix PR #1 bug: `supports_attestation()` is true **only when real evidence is attached**
  (remove the SE `set_attestation(nullopt)` that forced `true`).

### 6.3 Shared verifier `mpss-attest-verify`
```cpp
class AttestationVerifier {
public:
  struct Policy {
     std::function<std::vector<TrustAnchor>(AttestationFormat)> roots;   // pinned per format
     std::function<std::chrono::system_clock::time_point()>     clock;   // injectable (replay)
     std::function<bool(std::span<const std::byte> serial)>     is_revoked;
     AttestationSecurityLevel min_security_level;
     bool accept_vbs_self_asserted{false};  // MUST opt in; VBS is never accepted as real attestation by default
  };
  struct Result {
     bool ok{false};
     AttestationAssurance    assurance{AttestationAssurance::none};      // surfaced to the caller
     AttestationSecurityLevel security_level{AttestationSecurityLevel::unknown};
     std::string reason;
  };
  Result verify(const AttestationEvidence&, std::span<const std::byte> expected_nonce,
                std::span<const std::byte> expected_pubkey) const;
};
```
- Per-format verifiers behind one interface; injectable clock + roots + revocation.
- **VBS is never reported as `hardware_root_verified`.** A `windows_vbs_claim` always
  yields `assurance = vbs_self_asserted`, and `verify` **rejects it by default** unless
  `Policy.accept_vbs_self_asserted` is set — so a relying party cannot silently accept VBS
  as externally-verifiable hardware attestation.
- The PR #1 mock "PKI" is reduced to nonce issue/expire/replay bookkeeping + a call into
  this verifier; its ad-hoc blob parsing is deleted.

### 6.4 Public-key encoding (fixes PR #1 finding)
Verifier compares keys in **one canonical encoding: DER `SubjectPublicKeyInfo`**. Each
backend's `extract_key()` (raw uncompressed EC point today) is normalized to SPKI so
real evidence and CSR keys actually match.

---

## 7. Per-platform design

### 7.1 Android
- **Mechanism:** `KeyGenParameterSpec.Builder.setAttestationChallenge(nonce)` (≤128 B) +
  `KeyStore.getCertificateChain(alias)`. (Existing Java `GetAttestationCertificateChain`
  is correct and reused.)
- **Evidence:** leaf-cert ext `1.3.6.1.4.1.11129.2.1.17` → `KeyDescription` (challenge,
  `attestationSecurityLevel` ∈ {Software 0, TEE 1, StrongBox 2}); RKP adds ext `…2.1.30`.
- **Roots:** Google HW root (`android.googleapis.com/attestation/root`), revocation
  `…/attestation/status`; pin in-repo. Reject the public **software** root as a trust anchor.
- **Verify:** first (nearest-root) occurrence of the ext; chain to Google root; revocation;
  validity (mandatory for RKP); `challenge==nonce`; `level≥TEE`; `rootOfTrust`; leaf key == CSR key.
- **Use cases:** UC-A1 require StrongBox; UC-A2 reject unlocked bootloader; UC-A3 request
  (not require) → key created without evidence, caller informed.
- **Test cases:** TA-1 emulator create+parse (`level==Software`, CI); TA-2/3 captured
  TEE/StrongBox fixtures (offline); TA-4 tampered challenge → reject; TA-5 software-root
  chain → reject; TA-6 revoked serial → reject; TA-7 expired RKP cert → reject; TA-8
  extension-injection → only nearest-root ext trusted.
- **CI lane:** emulator (ubuntu KVM) for generation/parser; **offline fixture replay** for
  all trust decisions; device farm (Firebase/AWS) periodically refreshes fixtures.

### 7.2 Windows — TPM (production-verifiable lane)
- **Mechanism (measured):** `MS_PLATFORM_KEY_STORAGE_PROVIDER` + `NCryptCreateClaim`
  (`AUTHORITY_AND_SUBJECT` = TPM AIK-signed key attributes; `PLATFORM` = PCR quote), nonce
  via buffer type 49. EC P-256 works (1703-byte claim). Verify is **off-device**: parse
  the claim + AIK/EK chain to a **pinned manufacturer root** (`TrustedTpm.cab`).
- **Algorithm (decision #4):** use **EC** via **direct `NCryptCreateClaim`** (measured to
  work) + our own verifier against published EK roots. The Windows Server **AD CS
  enterprise-CA** key-attestation flow is **out of scope** — it's RSA-only, needs a
  domain-joined enterprise CA, and is redundant since our verifier already validates the
  claim against `TrustedTpm.cab`. (RSA + the CA path can be added later if a scenario needs it.)
- **Trust:** subject → AIK (bound to EK via `TPM2_ActivateCredential`) → EK cert → mfr root.
- **PR #1 fix:** the Windows backend created a VBS key but **never called
  `NCryptCreateClaim`** (empty chain + homemade blob = no attestation). Real generation
  must call `NCryptCreateClaim` with the nonce buffer.
- **Use cases:** UC-W1 enrol TPM-bound key, verify AIK→EK→mfr-root + nonce.
- **Test cases:** TW-1 swtpm/software structural round-trip (CI, labeled non-HW); TW-2
  captured real vTPM claim + AIK/EK chain (offline); TW-3 nonce mismatch → reject; TW-4
  EK re-rooted at untrusted CA → reject.
- **CI lane:** hosted runner = software/swtpm structural only (no TPM). Real TPM claims on a
  **self-hosted Azure Trusted-Launch (vTPM)** VM; offline replay for the verifier.

### 7.3 Windows — VBS / Key Guard (hosted-CI test lane)
- **Mechanism (measured):** `MS_KEY_STORAGE_PROVIDER` + `NCRYPT_USE_VIRTUAL_ISOLATION_FLAG`;
  `NCryptCreateClaim(VBS_ROOT / legacy)` → 1787-byte claim; `NCryptVerifyClaim` (details
  flag + imported public key) verifies. **Full generate→verify works on hosted
  windows-latest with no TPM.**
- **Trust reality (measured):** IDKS root is **per-machine/per-boot** (three distinct
  RSA-2048 roots; two same-image runners differ) → **no pinnable/published root → not
  externally verifiable.** Anchoring the per-boot IDKS requires a TPM (measured boot), at
  which point you'd use TPM directly.
- **Role:** **key protection** where no usable TPM exists, and a **hosted-CI E2E test lane**
  for the VBS attestation code path (real create→claim→parse→verify on every PR). **Not**
  presented as production-verifiable attestation.
- **Surfacing (decision #2 — must be unmistakable):** VBS evidence is emitted only under the
  distinct `windows_vbs_claim` format, and the verifier reports it as `vbs_self_asserted`
  and **rejects it by default** (explicit `accept_vbs_self_asserted` opt-in required). Any
  consumer therefore sees, unambiguously, that the evidence is VBS and is **not** proof of
  hardware provenance.
- **Test cases:** TV-1 generate→verify on hosted runner → VERIFIED (CI, self-verification,
  labeled test-only); TV-2 tampered claim → verify fails; TV-3 assert IDKS is *not* treated
  as a trust anchor by the production verifier.

### 7.4 Apple — App Attest: OUT OF SCOPE (decision #1: ACME only)
- App Attest attests the **app instance**, not a key, needs Apple's servers, and
  `isSupported=false` on macOS + Simulator. Per decision #1 it is **excluded** — it is not
  key attestation and would only mislead. The Apple format enum contains no `apple_app_attest`.

### 7.5 Apple — macOS/iOS ACME Managed Device Attestation (the real key path)
- **Mechanism:** ACME `device-attest-01`; the SE generates a hardware-bound key inside the
  ACME flow; Apple returns an X.509 chain (device props + nonce = `SHA256(token)`) to the
  Apple attestation CA. **Requires MDM-enrolled, supervised, physical Apple Silicon.**
- **Verify:** chain to pinned Apple Enterprise Attestation Root; nonce OID; validity; key
  binding — like Android.
- **Use cases:** UC-M1 enrol a managed Mac's SE key via org ACME CA; prove device + freshness.
- **Test cases:** TM-1 captured ACME leaf+chain fixture (offline); TM-2 nonce OID mismatch →
  reject; TM-3 non-Apple root → reject; TM-4 not-managed → `capability==none`.
- **CI lane:** **none on hosted/VM.** Offline fixture replay only; real capture requires a
  **persistent physical enrolled Mac** (self-hosted) + ACME CA (`nanoca`).

---

## 8. Testing strategy + CI matrix

Three layers; the first two run on **every PR** and constitute "E2E in CI".

1. **Offline verification E2E (every PR, all runners).** Committed real-hardware vectors
   (X.509 / CBOR / TPM claim) + pinned vendor roots + **mocked clock** + mocked revocation,
   run through `mpss-attest-verify`. Includes vendor golden vectors and tamper/negative cases.
2. **On-runner generation/structural (per runner).** Android emulator (software), iOS
   Simulator capability-gating + SE-key create, Windows software/swtpm structural, and the
   **Windows VBS full generate→verify** (the one real-attestation E2E that runs hosted).
3. **Real-hardware capture (periodic, out-of-band).** Self-hosted vTPM VM (TPM), device farm
   (Android TEE/StrongBox), physical enrolled Mac (ACME), real iPhone (App Attest). Refreshes
   Stage-1 vectors; not on every PR.

| Variant | Real-HW E2E hosted CI? | Needs self-hosted / device? | Offline replay? | CI approach |
|---|---|---|---|---|
| Android software | ✅ (not secure) | — | ✅ | emulator parser/gen tests |
| Android TEE/StrongBox | ❌ | device farm | ✅ | capture → offline replay vs Google root |
| Windows TPM | ❌ (no TPM) | self-hosted vTPM | ✅ | swtpm structural + offline replay |
| Windows VBS | ✅ generate→verify | — | ✅ | **on-runner E2E** (test-only) + tamper tests |
| Apple App Attest | ❌ | real iPhone | ✅ | golden + captured vectors, offline |
| Apple ACME | ❌ | physical enrolled Mac | ✅ | captured chain, offline |

**Vector hygiene:** vectors under `tests/vectors/<platform>/` with metadata (capture date,
device, expected nonce/level); clock pinned to capture date; roots pinned (never fetched live).

---

## 9. Staged rollout (stacked PRs — do NOT land as one)

0. **This design + spike** — freeze the evidence contract + verifier interface. *(no product code)*
1. **API + contract + delete the mock** — new `AttestationEvidence`/capability API,
   `mpss-attest-verify` skeleton; remove homemade statement/blob parsing + the `GTEST_SKIP`s;
   fix PR #1 bugs (SE `supports_attestation`, `nonce_key` hex padding, app-attest assign-before-check).
2. **Android real** (best anchored: X.509 + test CA + captured vectors).
3. **Windows** — TPM claim (`NCryptCreateClaim`, swtpm CI, vTPM capture) **+ VBS on-runner
   E2E test lane** (labeled test-only).
4. **Apple** — ACME verifier + captured vectors; App Attest only if in scope (§10).
5. **Verifier hardening + real-hardware capture lanes.**

---

## 10. Decisions (resolved 2026-07-19)

1. **Apple: ACME only.** Real Apple key attestation = ACME Managed Device Attestation on
   managed, physical Apple-Silicon devices. App Attest is **dropped** (not key attestation).
   Unmanaged Apple devices are **unsupported** for key attestation.
2. **Windows VBS = key-protection + CI-test-lane only, and unmistakable.** VBS uses the
   distinct `windows_vbs_claim` format; the verifier reports `vbs_self_asserted` and rejects
   it by default (opt-in required). Never presented as proper attestation.
3. **Real-hardware capture lanes approved** (self-hosted vTPM VM, device farm, physical
   enrolled Mac).
4. **Windows: EC via direct `NCryptCreateClaim`** + our verifier (published EK roots). The
   RSA-only AD CS enterprise-CA path is **out of scope** for now (redundant + heavy).

---

## 11. Impact on PR #1

Keep: public-API shape, registry→backend→`os::create_key` plumbing, Android Java chain
retrieval, SE key creation + `select_apple_attestation_selection`, OpenSSL test-CA harness,
mock nonce bookkeeping.
Delete: all `Build*Statement`, `parse_challenge_and_key`, raw-point↔DER compare, fake
`{0x30,0x84}` ACME cert, the `GTEST_SKIP` masks.
Fix: SE `supports_attestation` (#1), `nonce_key` hex padding (#5), app-attest assign-before-check UB (#6).

---

## 12. References (primary sources)

**Android:** developer.android.com/privacy-and-security/security-key-attestation ·
source.android.com/docs/security/features/keystore/attestation ·
android.googleapis.com/attestation/{root,status} · github.com/android/keyattestation

**Apple:** developer.apple.com/documentation/devicecheck/dcappattestservice (+ isSupported) ·
…/validating-apps-that-connect-to-your-server · …/attestation-object-validation-guide ·
W3C WebAuthn L2 §8.8 (OID 1.2.840.113635.100.8.2) ·
developer.apple.com/documentation/devicemanagement/acmecertificate · RFC 8555 ·
draft-ietf-acme-device-attest-08 · support.apple.com/guide/deployment/managed-device-attestation ·
apple.com/certificateauthority/private · github.com/brandonweeks/nanoca

**Windows:** learn.microsoft.com/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreateclaim
(+ ncryptverifyclaim, ncryptcreatepersistedkey) · learn.microsoft.com/windows/win32/seccng/key-storage-property-identifiers
(`VBS_ROOT_PUB`) · Windows SDK `ncrypt.h` (VBS structs, magic 'VRCH'/'VICH'/'VKAS') ·
learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation ·
go.microsoft.com/fwlink/?linkid=2097925 (TrustedTpm.cab) ·
learn.microsoft.com/azure/attestation/virtualization-based-security-protocol ·
learn.microsoft.com/azure/virtual-machines/trusted-launch

**CI / test pattern:** docs.github.com/actions/…/github-hosted-runners ·
github.com/actions/runner-images · github.com/tpm2-software/tpm2-tss (swtpm CI) ·
github.com/Yubico/java-webauthn-server (RealExamples.scala, Clock injection) ·
firebase.google.com/products/test-lab · aws.amazon.com/device-farm

**Firsthand measurements (2026-07-18/19):** dev-box + `windows-latest` VBS/TPM probes,
`macos-latest` App Attest/SE/enrollment probes, iOS-Simulator probes — captured via the
throwaway `attestation-capability-probe` workflow (removed after capture; results in §3).
