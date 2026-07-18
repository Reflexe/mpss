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

## Platform contracts

- **Android (`android_key_attestation`)**: validate nonce binding, key binding, and key-attestation structure (including cert-chain presence). In production, chain validation to Google hardware attestation roots must be enforced server-side.
- **Windows (`windows_tpm`)**: validate nonce binding and key binding from TPM-backed claim data. In production, chain validation to trusted TPM roots is required server-side.
- **Apple (`apple_app_attest`)**: validate App Attest evidence structure, nonce binding, and CSR-key possession binding. This is a weaker assurance than direct CSR-key non-exportability proof.

Apple App Attest demonstrates a genuine app instance on genuine Apple hardware with Secure Enclave support and key possession, but it does **not** provide the same non-exportability guarantee for the CSR key as Android hardware key attestation or Windows TPM claims.

ACME Managed Device Attestation is the stronger Apple managed-device alternative, but is intentionally out of scope here.

## Reference implementation seam

`tests/mock_pki/` is the in-process reference verifier used in tests. Real trust-chain-to-hardware-root validation is intentionally behind a pluggable seam and must be implemented by production PKI services.
