package crypto

import ()

// PIN block helpers mirroring psec.pinblock.encode_pinblock_iso_0 and the
// trans_pin flow (ISO 9564-1 Format 0 / ANSI X9.8).

// EncodePinblockISO0 builds an ISO-0 PIN block: format nibble (0), PIN length,
// PIN digits, padded with F, XORed with the PAN field.
func EncodePinblockISO0(pin, panHex string) ([]byte, error) {
	pinDigits := []byte(pin)
	if len(pinDigits) > 16 || len(pinDigits) < 4 {
		return nil, ErrInvalid{Msg: "pin must be 4-16 digits"}
	}
	if len(panHex) < 12 {
		return nil, ErrInvalid{Msg: "pan too short"}
	}
	// pin field (ISO 9564-1 Format 0): byte 0 = 0x0L (format 0, L = PIN
	// length), followed by the BCD PIN digits, padded with F.
	block := make([]byte, 8)
	block[0] = byte(len(pinDigits))
	for i := 0; i < len(pinDigits); i++ {
		d := pinDigits[i]
		if d < '0' || d > '9' {
			return nil, ErrInvalid{Msg: "pin must be numeric"}
		}
		if i%2 == 0 {
			block[1+i/2] = (d - '0') << 4
		} else {
			block[1+i/2] |= d - '0'
		}
	}
	for i := 1 + (len(pinDigits)+1)/2; i < 8; i++ {
		block[i] = 0xFF
	}

	// pan field: 0x0000 + the PAN without its check digit, right-aligned to 12
	// digits (rightmost 12), occupying bytes 2-7
	panDigits := panHex
	if len(panDigits) > 12 {
		panDigits = panDigits[len(panDigits)-12:]
	}
	panBlock := make([]byte, 8)
	for i := 0; i < 12; i++ {
		d := panDigits[i]
		if d < '0' || d > '9' {
			return nil, ErrInvalid{Msg: "pan must be numeric"}
		}
		if i%2 == 0 {
			panBlock[2+i/2] |= (d - '0') << 4
		} else {
			panBlock[2+i/2] |= d - '0'
		}
	}
	// pad rest with 0 already
	return xor(block, panBlock), nil
}
