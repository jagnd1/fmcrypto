package crypto

import (
	"bytes"
	"encoding/asn1"
	"math/big"
)

// Minimal DER encoder for CMS structures (PKCS#7 / RFC 5652). Go's stdlib has
// no CMS, so EnvelopedData/SignedData are assembled here with encoding/asn1
// for leaf values and explicit SEQUENCE/SET/context wrappers.

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRSASSA        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} // sha256WithRSA
	oidAES128CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidKBH           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1} // "data" used as attr type
	oidRandomNonce   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 25, 3}
)

const (
	tagSequence = 0x30
	tagSet      = 0x31
	tagContext0 = 0xA0 // [0] constructed
	tagContext1 = 0xA1 // [1] constructed
	tagPrim0    = 0x80 // [0] primitive
)

func derLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	case n <= 0xFFFF:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

// derWrap wraps body in a tag with a DER length.
func derWrap(tag byte, body []byte) []byte {
	out := make([]byte, 0, 1+len(derLength(len(body)))+len(body))
	out = append(out, tag)
	out = append(out, derLength(len(body))...)
	return append(out, body...)
}

func derSeq(children ...[]byte) []byte {
	var body []byte
	for _, c := range children {
		body = append(body, c...)
	}
	return derWrap(tagSequence, body)
}

func derSet(children ...[]byte) []byte {
	var body []byte
	for _, c := range children {
		body = append(body, c...)
	}
	return derWrap(tagSet, body)
}

// derContext wraps body in a constructed context-specific tag (implicit).
func derContext(tag byte, body []byte) []byte {
	return derWrap(tag, body)
}

// derExplicitContext wraps body in an explicit [n] EXPLICIT.
func derExplicitContext(n int, body []byte) []byte {
	return derContext(byte(0xA0+n), body)
}

func derOID(oid asn1.ObjectIdentifier) []byte {
	b, err := asn1.Marshal(oid)
	if err != nil {
		return nil
	}
	return b
}

func derInt(n int64) []byte {
	b, err := asn1.Marshal(n)
	if err != nil {
		return nil
	}
	return b
}

func derBigInt(n *big.Int) []byte {
	b, err := asn1.Marshal(n)
	if err != nil {
		return nil
	}
	return b
}

func derOctet(b []byte) []byte {
	enc, err := asn1.Marshal(b)
	if err != nil {
		return nil
	}
	return enc
}

func derRaw(b []byte) []byte { return b }

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// tlvRead parses one BER/DER TLV element (tag, content, rest).
func tlvRead(b []byte) (byte, []byte, []byte, error) {
	if len(b) < 2 {
		return 0, nil, nil, ErrInvalid{Msg: "tlv too short"}
	}
	tag := b[0]
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

// tlvChildren returns the child TLVs of a SEQUENCE/SET TLV.
func tlvChildren(tlv []byte) ([][]byte, error) {
	tag, content, rest, err := tlvRead(tlv)
	if err != nil || len(rest) != 0 || (tag != tagSequence && tag != tagSet) {
		return nil, ErrInvalid{Msg: "not a sequence"}
	}
	var out [][]byte
	for len(content) > 0 {
		full := content
		_, _, r, err := tlvRead(content)
		if err != nil {
			return nil, err
		}
		out = append(out, full[:len(full)-len(r)])
		content = r
	}
	return out, nil
}