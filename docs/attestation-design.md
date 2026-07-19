# Design: Real Hardware Key Attestation for MPSS (Windows, macOS, iOS, Android)

Status: **Draft — key decisions resolved 2026-07-19 (§10)**

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

**Consequences that shape the whole design:**
1. **Apple has no API to attest an arbitrary key.** The only real hardware **key**
   attestation on Apple is **ACME** (managed devices only).
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
- ID attestation and remote-provisioning backends.

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
   (Google root), Apple ACME (Apple Enterprise Attestation Root) all qualify. **VBS does not**
   (per-machine/per-boot IDKS). "Convenient" options like VBS don't deliver
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
| Apple ACME | `SHA256(ACME token)` in a leaf-cert OID | Apple attestation CA |
| Windows TPM | `NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE` (49) in the claim | TPM AIK → EK → mfr root |
| Windows VBS | nonce in `VRCH` report | per-boot IDKS (**unanchored w/o TPM**) |

The binding must never live in an unsigned, app-defined blob; it always lives in
vendor-signed evidence.

---

## 6. Architecture

### 6.1 Evidence contract
```cpp
enum class AttestationFormat {
    none,
    android_key_attestation,      // X.509 chain, ext 1.3.6.1.4.1.11129.2.1.17
    apple_acme_managed_device,    // X.509 chain (ACME device-attest-01) — the ONLY Apple path
    windows_tpm_claim,            // NCryptCreateClaim AUTHORITY_AND_SUBJECT / PLATFORM (TPM; externally verifiable)
    windows_vbs_claim             // NCryptCreateClaim VBS_ROOT / VBS_IDENTITY (VBS/Key Guard; NOT real attestation)
};

using CertChain   = std::vector<std::vector<std::byte>>;  // DER X.509, leaf-first (Android, Apple ACME)
using NCryptClaim = std::vector<std::byte>;               // opaque NCrypt claim blob (Windows)

struct AttestationEvidence {
    AttestationFormat format{AttestationFormat::none};
    std::variant<std::monostate, CertChain, NCryptClaim> payload;  // std::monostate == format none
};
```
- No app-defined framing; the nonce/public key are read from the *signed* structure.
- The `payload` variant carries the format-appropriate representation: a `CertChain` for
  the X.509 formats (Android, Apple ACME) or an `NCryptClaim` for the Windows formats.
- **The format IS the signal.** `windows_vbs_claim` is a first-class format, distinct from
  `windows_tpm_claim` and never folded into it — so producer and relying party always see
  "this is VBS." No separate assurance concept: a relying party that requires real
  attestation simply refuses the `windows_vbs_claim` format.

### 6.2 Capability-scoped API
Keep the named-key `Create(..., attestation)` for **Android/Windows/Apple** (which attest a
named key). Add an honest capability query:
```cpp
enum class AttestationCapability { none, key_attestation };
[[nodiscard]] static AttestationCapability attestation_capability(std::string_view backend = "os");
```
- Android/Windows/Apple → `key_attestation` (all attest the key itself; Apple via ACME,
  which certifies the created key — hence `key_attestation`, not a device-identity concept).
- **Apple key attestation is ACME only**, on managed, physical Apple-Silicon devices;
  `Create(..., attestation)` on an unmanaged Apple device produces no evidence.
- `supports_attestation()` is true **only when real evidence is attached**.

### 6.3 Shared verifier `mpss-attest-verify`
```cpp
class AttestationVerifier {
public:
  struct Policy {
     std::function<std::vector<TrustAnchor>(AttestationFormat)> roots;   // pinned per format
     std::function<std::chrono::system_clock::time_point()>     clock;   // injectable (replay)
     std::function<bool(std::span<const std::byte> serial)>     is_revoked;
  };
  struct Result {
     bool ok{false};
     AttestationFormat format{AttestationFormat::none};   // caller distinguishes real vs VBS by this
     std::string reason;
  };
  Result verify(const AttestationEvidence&, std::span<const std::byte> expected_nonce,
                std::span<const std::byte> expected_pubkey) const;
};
```
- Per-format verifiers behind one interface; injectable clock + roots + revocation.
- **The format carries the distinction.** `verify` echoes the `format` in the result; a
  relying party that requires externally-verifiable attestation refuses the
  `windows_vbs_claim` format (it can't chain to a published root). No separate assurance
  flag — the format alone tells the caller it is VBS, not TPM.
- The mock "PKI" is reduced to nonce issue/expire/replay bookkeeping + a call into
  this verifier; there is no ad-hoc blob parsing.

### 6.4 Public-key encoding
Verifier compares keys in **one canonical encoding: DER `SubjectPublicKeyInfo`**. Each
backend's `extract_key()` (raw uncompressed EC point today) is normalized to SPKI so
real evidence and CSR keys actually match. SPKI is key-type-agnostic, so the same
comparison covers both EC and RSA keys.

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
  via buffer type 49. Both EC P-256 (1703-byte claim) and RSA-2048 (2853-byte claim) work.
  Verify is **off-device**: parse the claim + AIK/EK chain to a **pinned manufacturer root**
  (`TrustedTpm.cab`).
- **Algorithm (decision #4):** use **EC and RSA** via **direct `NCryptCreateClaim`** (both
  measured to work: EC P-256 = 1703-byte claim, RSA-2048 = 2853-byte claim) + our own
  verifier against published EK roots. The Windows Server **AD CS enterprise-CA**
  key-attestation flow stays **out of scope** — it needs a domain-joined enterprise CA and
  is redundant since our verifier already validates the claim against `TrustedTpm.cab`.
- **Trust:** subject → AIK (bound to EK via `TPM2_ActivateCredential`) → EK cert → mfr root.
- **Real generation** must call `NCryptCreateClaim` with the nonce buffer (buffer type 49);
  a key alone, without a claim, is not attestation.
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
  **distinct `windows_vbs_claim` format** (never the TPM format). The format alone tells any
  consumer, unambiguously, that this is VBS — not TPM and not externally-verifiable
  provenance. A relying party requiring real attestation simply refuses that format.
- **Test cases:** TV-1 generate→verify on hosted runner → VERIFIED (CI, self-verification,
  labeled test-only); TV-2 tampered claim → verify fails; TV-3 assert IDKS is *not* treated
  as a trust anchor by the production verifier.

### 7.4 Apple — macOS/iOS ACME Managed Device Attestation (the real key path)
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
   (Android TEE/StrongBox), physical enrolled Mac (ACME). Refreshes
   Stage-1 vectors; not on every PR.

| Variant | Real-HW E2E hosted CI? | Needs self-hosted / device? | Offline replay? | CI approach |
|---|---|---|---|---|
| Android software | ✅ (not secure) | — | ✅ | emulator parser/gen tests |
| Android TEE/StrongBox | ❌ | device farm | ✅ | capture → offline replay vs Google root |
| Windows TPM | ❌ (no TPM) | self-hosted vTPM | ✅ | swtpm structural + offline replay |
| Windows VBS | ✅ generate→verify | — | ✅ | **on-runner E2E** (test-only) + tamper tests |
| Apple ACME | ❌ | physical enrolled Mac | ✅ | captured chain, offline |

**Vector hygiene:** vectors under `tests/vectors/<platform>/` with metadata (capture date,
device, expected nonce/level); clock pinned to capture date; roots pinned (never fetched live).

### 8.1 How to verify on real hardware

The hosted CI lanes cannot exercise real secure hardware (except Windows VBS). To capture
or re-verify genuine evidence, run the per-platform generation manually on real hardware,
then replay it offline through `mpss-attest-verify`:

- **Apple ACME:** on an **MDM-enrolled, supervised, physical Apple-Silicon Mac**, drive the
  ACME `device-attest-01` flow through the org ACME CA (e.g. `nanoca`); verify the returned
  X.509 chain against the pinned Apple Enterprise Attestation Root.
- **Android Key Attestation:** on a **real Android device** (or a device-farm device —
  Firebase Test Lab / AWS Device Farm) covering **both TEE and StrongBox**, create a key
  with the challenge and export `KeyStore.getCertificateChain`; verify against the Google
  hardware root.
- **Windows TPM:** on a **self-hosted box with a real (or vTPM) TPM** (e.g. an Azure
  Trusted-Launch VM), create the key via `MS_PLATFORM_KEY_STORAGE_PROVIDER` and call
  `NCryptCreateClaim`; verify the AIK/EK chain against `TrustedTpm.cab`.
- **Windows VBS:** on any **hosted runner** (no TPM needed), the full create→claim→verify
  path runs **on-runner** via `NCryptVerifyClaim` — a test lane only, never externally
  verifiable.

Captured evidence is committed under `tests/vectors/<platform>/` and replayed offline on
every PR with a pinned clock and pinned roots.

---

## 9. Staged rollout (stacked PRs — do NOT land as one)

0. **This design + spike** — freeze the evidence contract + verifier interface. *(no product code)*
1. **API + contract** — the `AttestationEvidence`/capability API and the
   `mpss-attest-verify` skeleton; backends report capability but emit no evidence yet.
2. **Android real** (best anchored: X.509 + test CA + captured vectors).
3. **Windows** — TPM claim (`NCryptCreateClaim`, swtpm CI, vTPM capture) **+ VBS on-runner
   E2E test lane** (labeled test-only).
4. **Apple** — ACME verifier + captured vectors.
5. **Verifier hardening + real-hardware capture lanes.**

---

## 10. Decisions (resolved 2026-07-19)

1. **Apple: ACME only.** Real Apple key attestation = ACME Managed Device Attestation on
   managed, physical Apple-Silicon devices. Unmanaged Apple devices are **unsupported** for
   key attestation.
2. **Windows VBS = key-protection + CI-test-lane only, and unmistakable.** The signal is the
   **format**: VBS uses the distinct `windows_vbs_claim` format (never the TPM format), so a
   consumer always sees it's VBS. No separate assurance concept; a relying party requiring
   real attestation refuses that format. Never presented as proper attestation.
3. **Real-hardware capture lanes approved** (self-hosted vTPM VM, device farm, physical
   enrolled Mac).
4. **Windows: EC and RSA via direct `NCryptCreateClaim`** + our verifier (published EK
   roots). Both key types produce a working claim (measured: EC P-256 = 1703 bytes,
   RSA-2048 = 2853 bytes). The AD CS enterprise-CA path stays **out of scope** (redundant
   with our verifier + heavy).

---

## 11. References (primary sources)

**Android:** developer.android.com/privacy-and-security/security-key-attestation ·
source.android.com/docs/security/features/keystore/attestation ·
android.googleapis.com/attestation/{root,status} · github.com/android/keyattestation

**Apple:** developer.apple.com/documentation/devicemanagement/acmecertificate · RFC 8555 ·
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
`macos-latest` SE/enrollment probes, iOS-Simulator probes — captured via the
throwaway `attestation-capability-probe` workflow (removed after capture; results in §3).
