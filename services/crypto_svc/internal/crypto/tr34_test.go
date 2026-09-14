package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// readTlv parses one BER/DER TLV element: returns tag, content, and remaining.
func readTlv(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, ErrInvalid{Msg: "tlv too short"}
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < i+n {
			return 0, nil, nil, ErrInvalid{Msg: "bad length"}
		}
		l = 0
		for _, x := range b[i : i+n] {
			l = l<<8 | int(x)
		}
		i += n
	}
	if len(b) < i+l {
		return 0, nil, nil, ErrInvalid{Msg: "tlv truncated"}
	}
	return tag, b[i : i+l], b[i+l:], nil
}

// childrenTLVs returns the full child TLVs of a SEQUENCE/SET TLV.
func childrenTLVs(t *testing.T, der []byte) [][]byte {
	t.Helper()
	tag, content, rest, err := readTlv(der)
	if err != nil || len(rest) != 0 || (tag != 0x30 && tag != 0x31) {
		t.Fatalf("not a sequence: %x", der[:min(len(der), 24)])
	}
	var out [][]byte
	for len(content) > 0 {
		full := content
		_, _, r, err := readTlv(content)
		if err != nil {
			t.Fatalf("child: %v", err)
		}
		out = append(out, full[:len(full)-len(r)])
		content = r
	}
	return out
}

// childrenOfContent reads full child TLVs from raw (already unwrapped) content,
// e.g. the payload of an IMPLICIT context tag.
func childrenOfContent(t *testing.T, content []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(content) > 0 {
		full := content
		_, _, r, err := readTlv(content)
		if err != nil {
			t.Fatalf("child: %v", err)
		}
		out = append(out, full[:len(full)-len(r)])
		content = r
	}
	return out
}

// tlvValue returns the content (value) of a TLV.
func tlvValue(t *testing.T, der []byte) []byte {
	t.Helper()
	_, c, _, err := readTlv(der)
	if err != nil {
		t.Fatalf("value: %v", err)
	}
	return c
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mustSelfSigned(t *testing.T, key *rsa.PrivateKey, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return der
}

func TestTr34Export(t *testing.T) {
	kdhKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	krdKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kdhCert := mustSelfSigned(t, kdhKey, "KDH")
	krdCert := mustSelfSigned(t, krdKey, "KRD")

	// wrap a KEK under the LMK
	kek, err := randomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	kbpk, err := WrapKey(AlgoA128, testLMK(t), kek, "")
	if err != nil {
		t.Fatal(err)
	}
	kdhSkDER, err := x509.MarshalPKCS8PrivateKey(kdhKey)
	if err != nil {
		t.Fatal(err)
	}
	kdhSkLMK, err := WrapKey(AlgoR2K, testLMK(t), kdhSkDER, "")
	if err != nil {
		t.Fatal(err)
	}

	sd, err := Tr34Export(testLMK(t), []byte(kbpk), krdCert, kdhCert, kdhSkLMK)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// ContentInfo{signedData, [0] SignedData}
	ci := childrenTLVs(t, sd)
	signedDataTLV := tlvValue(t, ci[1])
	sdChildren := childrenTLVs(t, signedDataTLV)

	// sdChildren: [ver, digestAlgs SET, encapContentInfo, signerInfos SET]
	encap := childrenTLVs(t, sdChildren[2])
	// eContent is [0] EXPLICIT OCTET STRING → unwrap to the EnvelopedData CI
	octetTLV := tlvValue(t, encap[1])
	edDER := tlvValue(t, octetTLV)

	edCI := childrenTLVs(t, edDER)
	edTLV := tlvValue(t, edCI[1])
	ed := childrenTLVs(t, edTLV) // EnvelopedData

	// ed: [ver, recipientInfos SET, encryptedContentInfo]
	recipients := childrenTLVs(t, ed[1])
	ktri := childrenOfContent(t, tlvValue(t, recipients[0])) // [0] IMPLICIT ktri
	// ktri: [ver, rid, keyEncAlgo, encryptedKey]
	ek := tlvValue(t, ktri[3])

	// encryptedContentInfo: [oid, alg{oid, iv}, [0] ec]
	eci := childrenTLVs(t, ed[2])
	alg := childrenTLVs(t, eci[1])
	iv := tlvValue(t, alg[1])
	ec := tlvValue(t, eci[2])

	// recover CEK via RSA-OAEP, then decrypt ec back to the KEK
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, krdKey, ek, nil)
	if err != nil {
		t.Fatalf("oaep decrypt: %v", err)
	}
	clear, err := aesCBCDecrypt(cek, iv, ec)
	if err != nil {
		t.Fatalf("aes decrypt: %v", err)
	}
	clear, err = pkcs7Unpad(clear, 16)
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	if !equalBytes(clear, kek) {
		t.Fatalf("recovered KEK mismatch: got %x want %x", clear, kek)
	}

	// Verify the SignedData signature over the signedAttrs
	signerInfos := childrenTLVs(t, sdChildren[3])
	si := childrenTLVs(t, signerInfos[0])
	// signerInfo: [ver, sid, digestAlg, [0] signedAttrs, sigAlg, signature]
	// The [0] IMPLICIT SET full TLV is exactly what was signed.
	attrsTLV := si[3]
	sig := tlvValue(t, si[5])

	digest := sha256.Sum256(attrsTLV)
	if err := rsa.VerifyPKCS1v15(&kdhKey.PublicKey, rsaHash(AlgoR2K), digest[:], sig); err != nil {
		t.Fatalf("signedattrs signature invalid: %v", err)
	}
}
