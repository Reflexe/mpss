// Independent CI verifier for the mpss VBS offline attestation bundle.
// Reuses google/go-attestation (the reference implementation) for the hard parts:
//   - quote signature + nonce + pcrDigest  (AKPublic.Verify)
//   - TCG event-log replay == quoted PCRs   (EventLog.Verify)
// then does the VBS-specific step: the IDK measured into the log signed the vsm_report.
package main

import (
	_ "crypto/sha1"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/google/go-attestation/attest"
)

type bundle struct {
	AttData struct {
		ReportSigned struct {
			TpmAttData struct {
				SrtmBootLog  string `json:"srtm_boot_log"`
				CurrentClaim string `json:"current_claim"`
				AikPub       struct {
					N string `json:"n"`
					E string `json:"e"`
				} `json:"aik_pub"`
			} `json:"tpm_att_data"`
		} `json:"report_signed"`
		VsmReport string `json:"vsm_report"`
	} `json:"att_data"`
}

func b64u(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "base64url decode: %v\n", err)
		os.Exit(2)
	}
	return b
}

func le32(b []byte, o uint32) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func be16(b []byte, o int) uint16    { return binary.BigEndian.Uint16(b[o:]) }

func step(ok bool, name, detail string) bool {
	mark := "FAIL"
	if ok {
		mark = "PASS"
	}
	fmt.Printf("  [%s] %-42s %s\n", mark, name, detail)
	return ok
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vbsverify <bundle.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read bundle: %v\n", err)
		os.Exit(2)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		fmt.Fprintf(os.Stderr, "parse bundle json: %v\n", err)
		os.Exit(2)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0x40 + i) // fixture challenge; real callers pass the relying-party nonce
	}

	td := b.AttData.ReportSigned.TpmAttData
	srtmLog := b64u(td.SrtmBootLog)
	tpla := b64u(td.CurrentClaim)
	vsm := b64u(b.AttData.VsmReport)
	aik := &rsa.PublicKey{
		N: new(big.Int).SetBytes(b64u(td.AikPub.N)),
		E: int(new(big.Int).SetBytes(b64u(td.AikPub.E)).Int64()),
	}

	// Parse 'TPLA': little-endian header; sig=TPMT_SIGNATURE, quote=TPMS_ATTEST, then 24 raw PCRs.
	cbSig, cbQuote, cbPcrs := le32(tpla, 12), le32(tpla, 16), le32(tpla, 20)
	o := uint32(24)
	sig := tpla[o : o+cbSig]
	o += cbSig
	quote := tpla[o : o+cbQuote]
	o += cbQuote
	pcrsBlob := tpla[o : o+cbPcrs]

	hashAlg := crypto.SHA1
	if be16(sig, 2) == 0x000b {
		hashAlg = crypto.SHA256
	}
	pcrs := make([]attest.PCR, 24)
	for i := 0; i < 24; i++ {
		pcrs[i] = attest.PCR{Index: i, Digest: pcrsBlob[i*32 : (i+1)*32], DigestAlg: crypto.SHA256}
	}

	fmt.Println("go-attestation verification of mpss VBS bundle:")
	akPub := &attest.AKPublic{Public: aik, Hash: hashAlg}
	q := attest.Quote{Quote: quote, Signature: sig}
	all := true

	qErr := akPub.Verify(q, pcrs, nonce)
	qDetail := "AIK-signed quote valid"
	if qErr != nil {
		qDetail = qErr.Error()
	}
	all = step(qErr == nil, "quote sig + nonce + pcrDigest (go-attestation)", qDetail) && all

	el, elErr := attest.ParseEventLog(srtmLog)
	var events []attest.Event
	if elErr == nil {
		events, elErr = el.Verify(pcrs)
	}
	elDetail := fmt.Sprintf("%d events replay to the quoted PCRs", len(events))
	if elErr != nil {
		elDetail = elErr.Error()
	}
	all = step(elErr == nil, "event-log replay == PCRs (go-attestation)", elDetail) && all

	idkOk, idkDetail := verifyVsmReport(vsm, srtmLog)
	all = step(idkOk, "IDK in measured boot signed vsm_report (VBS)", idkDetail) && all

	fmt.Println()
	if all {
		fmt.Println("RESULT: VALID -- genuine, externally-verifiable VBS attestation.")
		os.Exit(0)
	}
	fmt.Println("RESULT: NOT fully verified (see failing step above).")
	os.Exit(1)
}

// verifyVsmReport parses the NCrypt VBS claim frame and finds the IDK (an RSA-2048 key measured into
// the boot log) that signs the claim report via RSA-PSS/SHA-256.
func verifyVsmReport(vsm, srtmLog []byte) (bool, string) {
	if len(vsm) < 36 {
		return false, "vsm_report too small"
	}
	cbAttr, cbNonce, cbReport, cbSig := le32(vsm, 20), le32(vsm, 24), le32(vsm, 28), le32(vsm, 32)
	o := uint32(36) + cbAttr + cbNonce
	if uint32(len(vsm)) < o+cbReport+cbSig {
		return false, "vsm_report frame inconsistent"
	}
	report := vsm[o : o+cbReport]
	claimSig := vsm[o+cbReport : o+cbReport+cbSig]
	reportDigest := sha256.Sum256(report)

	for i := 0; i+3+256 <= len(srtmLog); i++ {
		if srtmLog[i] == 0x01 && srtmLog[i+1] == 0x00 && srtmLog[i+2] == 0x01 {
			idk := &rsa.PublicKey{N: new(big.Int).SetBytes(srtmLog[i+3 : i+3+256]), E: 65537}
			if rsa.VerifyPSS(idk, crypto.SHA256, reportDigest[:], claimSig, &rsa.PSSOptions{SaltLength: 32}) == nil {
				return true, "IDK found in measured boot log; vsm_report signature valid"
			}
		}
	}
	return false, "no IDK in this log verifies vsm_report (expected on a resumed VM; a clean boot's SRTM log carries it)"
}
