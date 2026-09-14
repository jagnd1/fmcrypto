package crypto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Certificate and CRL construction. The TBS structure is built here and the
// FINAL SIGNING is deliberately left to the HSM sign API (AsymSign via the
// service GenSign path) so real HSM (PS/AT) signatures match — libraries are
// never used to sign. Callers: build TBS → HSM-sign → pack.

// signAlgoOID maps an Algo to its X.509 signature-algorithm OID.
func signAlgoOID(algo Algo) asn1.ObjectIdentifier {
	switch algo {
	case AlgoECP256:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2} // ecdsa-with-SHA256
	case AlgoECP384:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3} // ecdsa-with-SHA384
	case AlgoECP521:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4} // ecdsa-with-SHA512
	case AlgoR2K:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} // sha256WithRSA
	case AlgoR3K:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12} // sha384WithRSA
	case AlgoR4K:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13} // sha512WithRSA
	}
	return nil
}

var (
	oidExtensionSKI       = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage  = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionBasicCons = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionAKI       = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionReason    = asn1.ObjectIdentifier{2, 5, 29, 21}
)

func derNull() []byte { return []byte{0x05, 0x00} }

func derBool(v bool) []byte {
	b := byte(0)
	if v {
		b = 0xFF
	}
	return []byte{0x01, 0x01, b}
}

// derBitString encodes an OCTET of bits with the given number of unused bits.
func derBitString(bytes []byte, unused int) []byte {
	return derWrap(0x03, append([]byte{byte(unused)}, bytes...))
}

func derTime(t time.Time) []byte {
	b, err := asn1.Marshal(t)
	if err != nil {
		return nil
	}
	return b
}

func derName(n *pkix.Name) []byte {
	b, err := asn1.Marshal(n.ToRDNSequence())
	if err != nil {
		return nil
	}
	return b
}

// x509Extension builds an Extension: SEQUENCE{ extnID, critical?, extnValue }.
func x509Extension(oid asn1.ObjectIdentifier, critical bool, extnValue []byte) []byte {
	parts := [][]byte{derOID(oid)}
	if critical {
		parts = append(parts, derBool(true))
	}
	return derSeq(append(parts, derOctet(extnValue))...)
}

// signatureAlgoField is the X.509 "signature" / "signatureAlgorithm" SEQUENCE.
func signatureAlgoField(algo Algo) []byte {
	return derSeq(derOID(signAlgoOID(algo)), derNull())
}

// subjectKeyID is the RFC 5280-style SKI (SHA-256 of the SPKI DER).
func subjectKeyIDFromSPKI(spki []byte) []byte {
	d := sha256Sum(spki)
	return d
}

// CertTbsBuild builds the TBS certificate DER from a CSR. Returns the TBS and
// the signing algorithm (from the issuer cert when present, else the request
// algo).
func CertTbsBuild(csrDER, issuerCertDER []byte, certLevel CertLevel, algo Algo) ([]byte, Algo, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, algo, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, algo, err
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, algo, err
	}

	var issuerName *pkix.Name
	signAlgo := algo
	if certLevel != CertLevelRootCA && len(issuerCertDER) > 0 {
		issuer, perr := x509.ParseCertificate(issuerCertDER)
		if perr != nil {
			return nil, algo, perr
		}
		issuerName = &issuer.Subject
		signAlgo = extractSignAlgoFromCert(issuer)
	} else {
		issuerName = &csr.Subject
	}

	now := time.Now().UTC()
	serial := big.NewInt(time.Now().UnixNano())

	// extensions
	extns := [][]byte{x509Extension(oidExtensionSKI, false, derOctet(subjectKeyIDFromSPKI(spki)))}
	if certLevel != CertLevelLeaf {
		extns = append(extns,
			x509Extension(oidExtensionBasicCons, true, derSeq(derBool(true))),
			x509Extension(oidExtensionKeyUsage, true, derBitString([]byte{0x86}, 1)), // digitalSignature|keyCertSign|crlSign
		)
	}

	tbs := derSeq(
		derContext(tagContext0, derInt(2)),                       // version [0] v3
		derBigInt(serial),                                        // serialNumber
		signatureAlgoField(signAlgo),                             // signature
		derName(issuerName),                                      // issuer
		derSeq(derTime(now), derTime(now.Add(365*24*time.Hour))), // validity
		derName(&csr.Subject),                                    // subject
		derRaw(spki),                                             // subjectPublicKeyInfo
		derContext(0xA3, derSeq(extns...)),                       // extensions [3]
	)
	return tbs, signAlgo, nil
}

// CertRenewTbs builds a renewal TBS from an existing certificate, keeping its
// identity (serial, subject, SPKI, CA attributes) with fresh validity.
func CertRenewTbs(certDER, issuerCertDER []byte, algo Algo) ([]byte, Algo, error) {
	old, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, algo, err
	}
	signAlgo := algo
	issuer := &old.Subject
	if len(issuerCertDER) > 0 {
		issuerCert, perr := x509.ParseCertificate(issuerCertDER)
		if perr != nil {
			return nil, algo, perr
		}
		issuer = &issuerCert.Subject
		signAlgo = extractSignAlgoFromCert(issuerCert)
	}

	now := time.Now().UTC()
	extns := [][]byte{x509Extension(oidExtensionSKI, false, derOctet(old.SubjectKeyId))}
	if old.IsCA {
		extns = append(extns,
			x509Extension(oidExtensionBasicCons, true, derSeq(derBool(true))),
			x509Extension(oidExtensionKeyUsage, true, derBitString([]byte{0x86}, 1)),
		)
	}

	tbs := derSeq(
		derContext(tagContext0, derInt(2)),
		derBigInt(old.SerialNumber),
		signatureAlgoField(signAlgo),
		derName(issuer),
		derSeq(derTime(now), derTime(now.Add(365*24*time.Hour))),
		derName(&old.Subject),
		derRaw(old.RawSubjectPublicKeyInfo),
		derContext(0xA3, derSeq(extns...)),
	)
	return tbs, signAlgo, nil
}

// CertPack assembles the final Certificate DER from the TBS and the HSM
// signature.
func CertPack(tbsDER, signature []byte, algo Algo) ([]byte, error) {
	return derSeq(
		derRaw(tbsDER),
		signatureAlgoField(algo),
		derBitString(signature, 0),
	), nil
}

// CRLTbsBuild builds the TBSCertList DER revoking cert, signed by issuer.
func CRLTbsBuild(certDER, issuerCertDER []byte, algo Algo, existingCRL string) ([]byte, Algo, error) {
	issuer, err := x509.ParseCertificate(issuerCertDER)
	if err != nil {
		return nil, algo, err
	}
	revoked, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, algo, err
	}
	now := time.Now().UTC()

	revCert := derSeq(derBigInt(revoked.SerialNumber), derTime(now))
	revokedList := [][]byte{revCert}
	if existingCRL != "" {
		if oldDER, herr := hexDecode(existingCRL); herr == nil {
			if old, perr := x509.ParseRevocationList(oldDER); perr == nil {
				for _, e := range old.RevokedCertificateEntries {
					revokedList = append(revokedList,
						derSeq(derBigInt(e.SerialNumber), derTime(e.RevocationTime)))
				}
			}
		}
	}

	// AKI extension: AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING }
	aki := derSeq(derContext(tagPrim0, issuer.SubjectKeyId))
	// Reason code: privilegeWithdrawn (bit 7)
	reason := derBitString([]byte{0x01}, 7)
	crlExtns := [][]byte{
		x509Extension(oidExtensionAKI, false, derRaw(aki)),
		x509Extension(oidExtensionReason, false, derRaw(reason)),
	}

	tbs := derSeq(
		derInt(1), // version v2 (plain INTEGER; required when extensions present)
		signatureAlgoField(algo),
		derName(&issuer.Subject),
		derTime(now),
		derTime(now.Add(30*24*time.Hour)),
		derSeq(revokedList...),
		derContext(tagContext0, derSeq(crlExtns...)), // crlExtensions [0]
	)
	return tbs, algo, nil
}

// CRLPack assembles the final CertificateList DER.
func CRLPack(tbsDER, signature []byte, algo Algo) ([]byte, error) {
	return derSeq(
		derRaw(tbsDER),
		signatureAlgoField(algo),
		derBitString(signature, 0),
	), nil
}

// extractSignAlgoFromCert derives the signing algo from a certificate's
// signature algorithm.
func extractSignAlgoFromCert(cert *x509.Certificate) Algo {
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		return AlgoR2K
	case x509.SHA384WithRSA:
		return AlgoR3K
	case x509.SHA512WithRSA:
		return AlgoR4K
	case x509.ECDSAWithSHA256:
		return AlgoECP256
	case x509.ECDSAWithSHA384:
		return AlgoECP384
	case x509.ECDSAWithSHA512:
		return AlgoECP521
	}
	return AlgoR2K
}
