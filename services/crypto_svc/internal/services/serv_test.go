package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"testing"

	"cryptosvc/internal/crypto"
	"cryptosvc/internal/dto"
	"cryptosvc/internal/hsm"
)

func testLMK() []byte { return crypto.Lmk(nil) }

// genECKP builds an EC keypair and returns the skLMK (TR-31 blob string).
func genECKP(t *testing.T) string {
	t.Helper()
	_, sk, err := crypto.GenKP(crypto.AlgoECP256, testLMK())
	if err != nil {
		t.Fatalf("genkp: %v", err)
	}
	return string(sk)
}

// buildCSR builds a PKCS#10 CSR DER for the given private key DER.
func buildCSR(t *testing.T, skDER []byte) []byte {
	t.Helper()
	sk, err := x509.ParsePKCS8PrivateKey(skDER)
	if err != nil {
		t.Fatalf("parse sk: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Root-CA", Organization: []string{"FM"}},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, sk)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return csr
}

func TestPKICertLifecycle(t *testing.T) {
	gp := hsm.NewGP(testLMK())
	svc := NewServer(gp)
	ctx := context.Background()

	skLMK := genECKP(t)
	skDER, err := crypto.UnwrapKey(crypto.AlgoECP256, testLMK(), skLMK)
	if err != nil {
		t.Fatalf("unwrap sk: %v", err)
	}
	csrDER := buildCSR(t, skDER)
	csrB64 := base64.URLEncoding.EncodeToString(csrDER)

	// create a self-signed root CA cert
	resp, err := svc.CertCreate(ctx, dto.CertCreateReq{
		Csr:       csrB64,
		SkLmk:     base64.URLEncoding.EncodeToString([]byte(skLMK)),
		CertLevel: "ROOT_CA",
		Algo:      "ECP256",
	})
	if err != nil {
		t.Fatalf("cert create: %v", err)
	}
	certDER, err := base64.URLEncoding.DecodeString(resp.Cert)
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("root cert should be a CA")
	}
	if cert.Subject.CommonName != "Root-CA" {
		t.Fatalf("subject cn = %q", cert.Subject.CommonName)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("self-signed signature invalid: %v", err)
	}
	if err := cert.VerifyHostname(""); err != nil {
		// ignore — no SANs; signature check above is the real gate
	}

	// renew the cert
	renewed, err := svc.CertRenew(ctx, dto.CertUpdateReq{
		Cert:       resp.Cert,
		IssuerCert: resp.Cert,
		SkLmk:      base64.URLEncoding.EncodeToString([]byte(skLMK)),
		CertLevel:  "ROOT_CA",
		Algo:       "ECP256",
	})
	if err != nil {
		t.Fatalf("cert renew: %v", err)
	}
	renewedDER, _ := base64.URLEncoding.DecodeString(renewed.Cert)
	renewedCert, err := x509.ParseCertificate(renewedDER)
	if err != nil {
		t.Fatalf("parse renewed: %v", err)
	}
	if renewedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("renewed cert should keep the serial number")
	}
	if err := renewedCert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("renewed signature invalid: %v", err)
	}

	// CRL revoking the cert
	crlResp, err := svc.CrlMgmt(ctx, dto.CrlMgmtReq{
		Cert:       resp.Cert,
		IssuerCert: resp.Cert,
		SkLmk:      base64.URLEncoding.EncodeToString([]byte(skLMK)),
		Algo:       "ECP256",
	})
	if err != nil {
		t.Fatalf("crl: %v", err)
	}
	crlDER, err := base64.URLEncoding.DecodeString(crlResp.Crl)
	if err != nil {
		t.Fatalf("decode crl: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	if err := crl.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("crl signature invalid: %v", err)
	}
	if len(crl.RevokedCertificateEntries) == 0 {
		t.Fatal("crl should contain the revoked cert")
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("crl should revoke the cert serial")
	}
}

func TestPKIRSA(t *testing.T) {
	gp := hsm.NewGP(testLMK())
	svc := NewServer(gp)
	ctx := context.Background()

	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	skDER, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	skLMK, err := crypto.WrapKey(crypto.AlgoR2K, testLMK(), skDER, "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Int-CA", Organization: []string{"FM"}},
	}, sk)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	resp, err := svc.CertCreate(ctx, dto.CertCreateReq{
		Csr:       base64.URLEncoding.EncodeToString(csr),
		SkLmk:     base64.URLEncoding.EncodeToString([]byte(skLMK)),
		CertLevel: "INT_CA",
		Algo:      "R2K",
	})
	if err != nil {
		t.Fatalf("cert create: %v", err)
	}
	certDER, _ := base64.URLEncoding.DecodeString(resp.Cert)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("int ca should be a CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("self-signed rsa sig invalid: %v", err)
	}
}