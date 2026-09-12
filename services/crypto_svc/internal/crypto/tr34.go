package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// TR-34 key export: wraps a clear KEK into a CMS EnvelopedData (RSAES-OAEP
// recipient info) and signs it in a CMS SignedData, matching the service
// exp_tr34 operation.

const tr34KBH = "B0016K1TD00N0000"

// rsaPubFromSPKI parses an RSA SubjectPublicKeyInfo, tolerating the missing
// NULL parameters common in legacy certificates (Java/BouncyCastle).
func rsaPubFromSPKI(spkiDER []byte) (*rsa.PublicKey, error) {
	var spki struct {
		Alg struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue `asn1:"optional"`
		}
		Bit asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, err
	}
	if !spki.Alg.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}) {
		return nil, ErrInvalid{Msg: "recipient key must be rsa"}
	}
	var pkcs1 struct {
		N *big.Int
		E int
	}
	if _, err := asn1.Unmarshal(spki.Bit.Bytes, &pkcs1); err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: pkcs1.N, E: pkcs1.E}, nil
}

// recipientFromCert extracts the recipient's RSA public key, issuer name, and
// serial from a certificate, tolerating legacy SPKI encodings that Go's strict
// x509 parser rejects.
func recipientFromCert(certDER []byte) (*rsa.PublicKey, []byte, *big.Int, error) {
	if cert, err := x509.ParseCertificate(certDER); err == nil {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, nil, ErrInvalid{Msg: "recipient key must be rsa"}
		}
		return pub, cert.RawIssuer, cert.SerialNumber, nil
	}
	// lenient walk: certificate → tbs → [version?, serial, signature, issuer,
	// validity, subject, spki, ...]
	cert, err := tlvChildren(certDER)
	if err != nil || len(cert) < 1 {
		return nil, nil, nil, ErrInvalid{Msg: "bad certificate"}
	}
	tbs, err := tlvChildren(cert[0])
	if err != nil || len(tbs) < 7 {
		return nil, nil, nil, ErrInvalid{Msg: "bad tbs certificate"}
	}
	var serial *big.Int
	var issuer, spki []byte
	seqs := 0
	for _, field := range tbs {
		tag, _, _, rerr := tlvRead(field)
		if rerr != nil {
			return nil, nil, nil, rerr
		}
		switch tag {
		case 0x02: // INTEGER → serial number (first one)
			if serial == nil {
				_, v, _, _ := tlvRead(field)
				serial = new(big.Int).SetBytes(v)
			}
		case 0x30: // SEQUENCE → issuer Name (2nd), then SPKI (first RSA)
			seqs++
			if seqs == 2 {
				issuer = field
			} else if seqs > 2 {
				if pub, perr := rsaPubFromSPKI(field); perr == nil {
					spki = field
					_ = spki
					return pub, issuer, serial, nil
				}
			}
		}
	}
	return nil, nil, nil, ErrInvalid{Msg: "recipient cert fields missing"}
}

// tr34BuildRI builds the KeyTransRecipientInfo for the recipient certificate.
func tr34BuildRI(encCertDER, ek []byte) ([]byte, error) {
	_, issuerDER, serial, err := recipientFromCert(encCertDER)
	if err != nil {
		return nil, err
	}
	issuerSerial := derSeq(derRaw(issuerDER), derBigInt(serial))
	rid := issuerSerial // RecipientIdentifier → issuerAndSerialNumber (untagged CHOICE)

	oaepParams := derSeq(
		derSeq(derOID(oidSHA256)),                            // hashAlgorithm
		derSeq(derOID(oidMGF1), derSeq(derOID(oidSHA256))),   // maskGenAlgorithm
	)
	keyEncAlgo := derSeq(derOID(oidRSAESOAEP), oaepParams)

	ktriChildren := []byte{}
	ktriChildren = concat(ktriChildren, derInt(0))
	ktriChildren = concat(ktriChildren, rid)
	ktriChildren = concat(ktriChildren, keyEncAlgo)
	ktriChildren = concat(ktriChildren, derOctet(ek))
	// RecipientInfo CHOICE → [0] IMPLICIT KeyTransRecipientInfo (tag replaces SEQUENCE)
	return derWrap(tagContext0, ktriChildren), nil
}

// Tr34BuildED produces the CMS EnvelopedData DER (not ContentInfo-wrapped).
func Tr34BuildED(krdCertDER, kekClear []byte) ([]byte, []byte, error) {
	keClear, err := randomBytes(16)
	if err != nil {
		return nil, nil, err
	}
	iv, err := randomBytes(16)
	if err != nil {
		return nil, nil, err
	}
	// encrypt the KEK under the content-encryption key (AES-128-CBC)
	padded, err := pkcs7Pad(kekClear, 16)
	if err != nil {
		return nil, nil, err
	}
	ec, err := aesCBCEncrypt(keClear, iv, padded)
	if err != nil {
		return nil, nil, err
	}

	// RSA-OAEP encrypt the CEK under the recipient's public key
	rsaPub, _, _, err := recipientFromCert(krdCertDER)
	if err != nil {
		return nil, nil, err
	}
	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, keClear, nil)
	if err != nil {
		return nil, nil, err
	}

	ri, err := tr34BuildRI(krdCertDER, ek)
	if err != nil {
		return nil, nil, err
	}
	encContentInfo := derSeq(
		derOID(oidData),
		derSeq(derOID(oidAES128CBC), derOctet(iv)),
		derContext(tagPrim0, ec), // encryptedContent [0] IMPLICIT OCTET STRING
	)
	ed := derSeq(derInt(0), derSet(ri), encContentInfo)
	return ed, keClear, nil
}

// Tr34BuildSD produces the CMS SignedData ContentInfo DER signing edDER.
func Tr34BuildSD(kdhCertDER []byte, skLMK string, lmk []byte, edDER []byte) ([]byte, error) {
	_, issuerDER, serial, err := recipientFromCert(kdhCertDER)
	if err != nil {
		return nil, err
	}
	hashED := sha256.Sum256(edDER)

	kbh := []byte(tr34KBH)
	nonce, err := randomBytes(16)
	if err != nil {
		return nil, err
	}

	signedAttrsChildren := concat(
		derSeq(derOID(oidContentType), derSet(derOID(oidData))),
		derSeq(derOID(oidMessageDigest), derSet(derOctet(hashED[:]))),
		derSeq(derOID(oidKBH), derSet(derOctet(kbh))),
		derSeq(derOID(oidRandomNonce), derSet(derOctet(nonce))),
	)
	// signedAttrs [0] IMPLICIT SET — the context tag replaces the SET tag.
	signedAttrs := derWrap(tagContext0, signedAttrsChildren)

	// sign the signed-attributes SET (RSA-SHA256) with the KDH key
	digest := sha256.Sum256(signedAttrs)
	signature, err := AsymSignDigest(AlgoR2K, lmk, skLMK, digest[:])
	if err != nil {
		return nil, err
	}

	sid := derSeq(derRaw(issuerDER), derBigInt(serial))
	signerInfo := derSeq(
		derInt(1),                              // version
		sid,                                    // issuerAndSerialNumber
		derSeq(derOID(oidSHA256)),              // digestAlgorithm
		derRaw(signedAttrs),                    // signedAttrs [0] IMPLICIT SET
		derSeq(derOID(oidRSASSA)),              // signatureAlgorithm
		derOctet(signature),                    // signature
	)

	encapContentInfo := derSeq(derOID(oidData), derExplicitContext(0, derOctet(edDER)))
	signedData := derSeq(
		derInt(1),                                          // version v1
		derSet(derSeq(derOID(oidSHA256))),                  // digestAlgorithms
		encapContentInfo,                                   // eContent (wraps edDER)
		derSet(signerInfo),                                 // signerInfos
	)
	return derSeq(derOID(oidSignedData), derExplicitContext(0, signedData)), nil
}

// Tr34Export performs the full TR-34 key export: unwraps the KEK under the
// LMK, wraps it in a CMS EnvelopedData (ContentInfo) for krdCert, and signs the
// result with the KDH private key. Returns the CMS SignedData ContentInfo DER.
func Tr34Export(lmk []byte, kbpk, krdCert, kdhCert []byte, kdhSkLMK string) ([]byte, error) {
	kekClear, err := UnwrapKey(AlgoA128, lmk, string(kbpk))
	if err != nil {
		return nil, err
	}
	ed, _, err := Tr34BuildED(krdCert, kekClear)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid{}, err)
	}
	// eContent carries the EnvelopedData wrapped in a ContentInfo (id-envelopedData)
	edCI := derSeq(derOID(oidEnvelopedData), derExplicitContext(0, ed))
	return Tr34BuildSD(kdhCert, kdhSkLMK, lmk, edCI)
}