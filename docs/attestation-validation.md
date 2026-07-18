# Hardware attestation validation contract

This document defines the reference contract between MPSS clients and a PKI verifier.

## Nonce lifecycle

- The PKI service issues a fresh random challenge nonce.
- Nonces are single-use and short-lived (TTL enforced by the verifier).
- The client passes the nonce in `AttestationRequest`.
- The verifier rejects missing, expired, mismatched, or replayed nonces.

## Require flow

1. PKI issues challenge.
2. Client calls `KeyPair::Create(..., AttestationRequest{challenge, AttestationRequirement::require}, ...)`.
3. Client builds CSR with `extract_key()` and `sign_hash()`.
4. Client sends CSR + `AttestationEvidence`.
5. PKI verifies format, nonce binding, and CSR-key binding, then signs or rejects.

## Apple policy model

- `AppleAttestationPolicy::auto_select` (default): prefer ACME managed-device attestation when available, otherwise fallback to App Attest.
- `AppleAttestationPolicy::mdm_only`: require ACME managed-device attestation path. With `AttestationRequirement::require`, key creation fails when device enrollment/capability is unavailable.
- `AppleAttestationPolicy::app_attest_only`: force App Attest.

Apple managed-device detection/capability is exposed through Apple wrapper seams (`MPSS_IsManagedDeviceEnrollmentAvailable`, `MPSS_IsAcmeAttestationAvailable`) so backend policy decisions are deterministic and testable.

## Platform contracts

- **Android (`android_key_attestation`)**: validate nonce binding, key binding, and full certificate-chain verification to trusted roots. In production, chain validation to Google hardware attestation roots must be enforced server-side.
- **Windows (`windows_tpm`)**: validate nonce binding, key binding, and full certificate-chain verification to trusted TPM roots.
- **Apple (`apple_app_attest`)**: validate App Attest evidence structure, nonce binding, and CSR-key possession binding. This is a weaker assurance than direct CSR-key non-exportability proof.
- **Apple ACME PoC (`apple_acme_managed_device_attestation`)**: validate nonce binding, key binding, and full certificate-chain verification to trusted roots using the managed-device-style mock statement format. This is a test seam proof-of-concept, not a production ACME integration.

Apple App Attest demonstrates a genuine app instance on genuine Apple hardware with Secure Enclave support and key possession, but it does **not** provide the same non-exportability guarantee for the CSR key as Android hardware key attestation or Windows TPM claims.

ACME Managed Device Attestation is the stronger Apple managed-device alternative. This repository includes a **mock PKI PoC format** for CI and verification tests, while production ACME service integration remains out of scope.

## Reference implementation seam

`tests/mock_pki/` is the in-process reference verifier used in tests. It is exercised by `tests/attestation_tests.cpp` (unit CI path) and by the attestation full-flow E2E test in CI, while OpenSSL certificate-chain serialization E2E coverage runs via `tests/mpss_openssl_e2e_test.cpp`. The mock verifier performs real X.509 chain validation against configured trusted roots for Android/Windows/Apple-ACME evidence (mocking only the transport/service boundary). Production PKI integrations still own platform-root management and policy.
