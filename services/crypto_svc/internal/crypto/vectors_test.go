package crypto

import (
	"encoding/hex"
	"testing"

	"cryptosvc/internal/crypto/dukpt"
)

// Known-answer vectors for the service crypto contract (generated 2026-09-13
// and cross-validated against the legacy implementation).

const (
	vecLMK       = "7db3558f65166c13fd527827af999f4eac96e827d4ff47bf8bf870933fd228d6"
	vecAESBlob   = "D0112D0AB00E0000329ECD301383924607CB1204CA4F3BD731C72B33F01AA49A09FFB4DE541AFACFADD34D7CBA875007BC3982CEC1BF9BA8"
	vecTDESBlob  = "D0112P0TE00N00008CAAE15E2D385B2AB57E1E429B43F01ABDF23DFC993FCBEB740DA3D5C06F676872C1A3AD6CAAD31468E509E6CF71AA37"
	vecAESKey    = "2392F7EFE0FD617973018683673EA143"
	vecTDESKey   = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF"
	vecCMAC      = "e8b216d09fb3ed1eae4d3d75ba95e1c5"
	vecKCV       = "c6298d"
	vecEncrCBC   = "6afdb3c6d6b62256e127691ff676dc16"
	vecIPEK      = "f985f6fba877d10c558e39accd5d33ca"
	vecWorkingKey = "85e0534e60a25288c30a092280f1e400"
	vecBDK       = "FEDCBA9876543210F1F1F1F1F1F1F1F1"
	vecIksn      = "1234567890123456"

	vecECCPK   = "3059301306072a8648ce3d020106082a8648ce3d03010703420004073f42301709133397ed08bb581e3500b38bf89d93ac18df4aad884f481fce4d0f765b27368564485e6c57a290931572107cc39bafe15e0ed66485af4e4842cd"
	vecECCSkLmk = "D0336S0ES00E0000FA211B3BE2F1EE505D2093BE31A13FE594AC21A3B5181A9F3638B3CE1801ECD27D7EA52F35CF467B2CDBAEAA6F38F895AE37969E9A79BB0BFE6A83C433C2E87FE5E505E31B5B4AFA4209A4152A90609AA26F4D376083D7397B9C74BDB101B29E07359E3E5E94FF63D35E9CAD5C7D66F1EE0F7FC35DCF5C15B95DC764CA5D9A28AF9B1630FE49944B23B7FA729605537D86429E44737B917BBFAA486CC7EA0D00"
	vecEcdhVal = "9b2cef26f2057c11c2c918164865dbb0"

	vecRSAPk   = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b657e234cb9a1937efa973c6b6f14f84e7278eb53a59d772f40be94f8d4440a464c274b324180be5bdb5b3dbcb37a708654a92842437d68e796faa5891342814dc8c8136ed30205b610e69ffcc5c500678b01fcf90a990a8c77d08d0ac40d32b55f7df0c6384bc1f754c182d11dc23844e371edb48bf41a8eaeac5bfde724ba5f3c258d44922b3db730a7e36d35c794b5a5d1a45ad1ab4921e31bd819acc6e84aafb5f428c2715e6f8e57eb8c59a7eeaa799da8ab58fdf2f62718aeb3f1fc51a750142801474161a0006d5912e1a20423f72812174ee3fa1c7907db1fc9cf1cd5443340b038379ae57127cd02ca263f3cda9b8876367c47fea329d1d94b8200b0203010001"
	vecRSASkLmk = "D2512S0ES00E000019B57CED7FA8DDAD6C47BAC79F01BA10A514DC02C0FB71D3E8AB054D4EDF1471BB8805656AC23E3C01FDC96D2C7D06C8D795CBD7AF9B1935933EE385679380A956476F2EB81BFF927EB05415C21EA532FDA7734C7A5C75E0B449B68349D8CEC257E8DCD5135701D9066E4557A1731563DE847FAA3D8683A0F19A792E534C624943321691DBB522DCC57B31CDC2677958417DDBA9B464ED7457F8A43B791EDAE5573929BA9AFDA0036E7D2FBA8204A9F482B5DD35411DC53311D5FF7D5D14211D1FBBC7BAE0FC1B6C713F1A04B7D79F0381F8192FD9C23717664490FF8CA6658C3E13B4A06DD608A8822E89513A966BAFB8E63E76C60761FD65875ABBD78DF5E1C09FCE25DB4AC1336E6031EF0AD9BE88800323428C0C7A32F92BABC03AD47FEEB8AFB7B0FE97AE0834096C4FDE3203295E58896710AE5F274A31BEB7DDF1386426F93BDFA28326DA65D6E35D1CDDBCFB5401B5726374FF791493924A37F8A76F7D2D11BFE96165D3117AE4709782DFE5FD39AB3300C5D9FB85DAEE57ED38ECEFEC602C5F95D9D08AE70059FCD4AB73262A43B81D8B376C9BEA8728109CA405FD1016D97D2956BD05152AB291EB4C7B02EFC85AC15148D5A7B161F209B1F6EBA10BE1C5780304711259203959F351619FE33CDB57461B0F80356AB06C9D0A7926E5558A714D0501D8D3E01F83F6B3D0ADA3C85032526551A485780836C4DD84467873AA9B6DA1DDC65F0AF528158FB22FBD3794C80247386A7ECC5488B351076FE342BB2194B669E2B9C5CE8AC5B97B0A60DF7E687FBF1897F24EED0B3D2663FFB0C7BCDC97526FC874C4B35ABD0DAC02C7E6AB47018C33A2AF0D9787B5A51ABB73AD8B00518DB8A3B264737C78D14366AB582DE4EB2DA63087C704CB39B5991338B0927DD105AD17EBA46AE2034B8C99907003E9A92F60606BE70B42431EB5264E25BF80B58E2C9D84F5DB6B823942D184924583667164E46746D5FD3B4A84449F3772B25EDA4CB8D01E010510C24CF3F270C7E9ACD50BD7CE790546274B89F4611A5F6F7FB3C691D436B6754DF9BD3C500E9124146E5CFF10B0DF5052441A0EC35DBA58DBC6209F25AB68B6FEC1DCC948481A70AB0CBB5CC9A086E3C9F08997BC60AE95F3BC13D07C75909FEC806FFDF8AE6A2A3DA2871B075A60081D8CEAD7EE57669C2E80BFF2B76AB63329C79A40EA52AB096FF024A2D86778F3EEE337302B0E51D4896BE8B13AB3DDDDBFFD63884D10EBEAD1533C0747F43ED60733AFBADEEFB6A0F5F0B5A3117358DECADF8EB9074EF9A3B21CB1EDF2B739370736B3D6DD20AA446B950E54801DE47091BB0B40FC6E2E8BED06F9F9D5516E2711D2E48BC217FB0AD90E65D90CADBBDE3F9600FD2E68906BE6D296A20F56E0865425B00E1BA6AA8A8292844C46E4B826CB101023AF8724685E65ACBE7062314568FDFF208345122519A1D7F4B27B3D311731F26E93E0686EE7D30E36988AC2632B53F139E5876D04D05B1CDFB15553DC45EF8131705CEA221DE734368EF43AF1E87A22A053A3AF48666DEC1A3E616D53D479E76A8D726E124CFF89D4B5381D48E76618C065024902AE2FB96E4E5D2A9DF72FC90EE7B46EB428CEF8D1875D6AF0F588F61FE56631C10DA08D8380847558B0E815E5BD6B6414E29C8B2E0C916612434F1F0532FB3108C9DB4FEF45C269472E0D38EAE5A5F7261B2598B94B889F07D19F0BC54EBE9ED38F80FF80BD2A4C7FF96B7F6CE70DA8B6502E4CA0175C343B540D8EF1"
	vecRSASig  = "5412ba3d9bafde61fd7eaca6567cc31af766babf66335f2e7a33b8b1ba9a0993626b0430a635f31472f086d674a61686315ac9a3dd805e3b2875030be31f40d22f483cf6f7c6f103ec59f4492245f16a3911ce3cf1a41c8ddfd030f2f09af1e9176816f07c7a7c57ee79801744c703b9952d6dc807c19775a5639b09ebcb885c509abbbadf0a37175642407369fa5c082d93b25b4546ee96a68cf6670f90e13570a69cb0c43d5cc582809384f59297b83b4fb118ab9bf0c60ce6898227d4f95b2b22a788c4058dd24ca297dd806ee71f9f1d6fbc024db5318342e50270ac8ed6a774a42010c7023b7f1645d5e8fd67b52da1e425f8202211e59ae7581171b64e"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func testLMK(t *testing.T) []byte { return mustHex(t, vecLMK) }

// assertHexEq compares a value against an (uppercase) hex string case-insensitively.
func assertHexEq(t *testing.T, got []byte, wantHex string) {
	t.Helper()
	want := mustHex(t, wantHex)
	if !equalBytes(got, want) {
		t.Fatalf("mismatch:\n got  %x\n want %s", got, wantHex)
	}
}

func TestTR31UnwrapAES(t *testing.T) {
	key, err := UnwrapKey(AlgoA128, testLMK(t), vecAESBlob)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	assertHexEq(t, key, vecAESKey)
}

func TestTR31UnwrapTDES(t *testing.T) {
	key, err := UnwrapKey(AlgoTDES, testLMK(t), vecTDESBlob)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	assertHexEq(t, key, vecTDESKey)
}

func TestTR31WrapRoundTrip(t *testing.T) {
	key := mustHex(t, vecAESKey)
	blob, err := WrapKey(AlgoA128, testLMK(t), key, "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	back, err := UnwrapKey(AlgoA128, testLMK(t), blob)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !equalBytes(back, key) {
		t.Fatalf("round trip mismatch: %x", back)
	}
	// TDES round trip with tdes header
	key3 := mustHex(t, vecTDESKey)
	blob3, err := WrapKey(AlgoTDES, testLMK(t), key3, "")
	if err != nil {
		t.Fatalf("wrap tdes: %v", err)
	}
	back3, err := UnwrapKey(AlgoTDES, testLMK(t), blob3)
	if err != nil {
		t.Fatalf("unwrap tdes: %v", err)
	}
	if !equalBytes(back3, key3) {
		t.Fatalf("tdes round trip mismatch")
	}
}

func TestCMACAndKCV(t *testing.T) {
	cmac, err := Sign(AlgoA128, testLMK(t), vecAESBlob, mustHex(t, "1234567890"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	assertHexEq(t, cmac, vecCMAC)
	kcv, err := GetKCV(AlgoA128, testLMK(t), vecAESBlob)
	if err != nil {
		t.Fatalf("kcv: %v", err)
	}
	assertHexEq(t, kcv, vecKCV)
}

func TestEncryptDecryptCBC(t *testing.T) {
	iv := []byte("1234567812345678")
	msg := mustHex(t, "1234567812345678")
	ct, err := Encrypt(AlgoA128, testLMK(t), EncrModeCBC, vecAESBlob, iv, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	assertHexEq(t, ct, vecEncrCBC)
	pt, err := Decrypt(AlgoA128, testLMK(t), EncrModeCBC, vecAESBlob, iv, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	// The Python decrypt returns PKCS7-unpadded data ONLY when the plaintext is
	// not exactly one block long; an 8-byte message comes back as the padded
	// 16-byte block. Replicate that quirk exactly.
	assertHexEq(t, pt, "12345678123456780808080808080808")
	// ECB round trip
	ctECB, err := Encrypt(AlgoA128, testLMK(t), EncrModeECB, vecAESBlob, iv, msg)
	if err != nil {
		t.Fatalf("encrypt ecb: %v", err)
	}
	ptECB, err := Decrypt(AlgoA128, testLMK(t), EncrModeECB, vecAESBlob, iv, ctECB)
	if err != nil {
		t.Fatalf("decrypt ecb: %v", err)
	}
	assertHexEq(t, ptECB, "12345678123456780808080808080808")
}

func TestDUKPTVectors(t *testing.T) {
	bdk := mustHex(t, vecBDK)
	iksn := mustHex(t, vecIksn)
	ipek, err := (dukpt.Deriver{}).DeriveInitialKey(bdk, dukpt.AES128, iksn)
	if err != nil {
		t.Fatalf("derive initial: %v", err)
	}
	assertHexEq(t, ipek, vecIPEK)
	_, _, wk, err := (dukpt.Deriver{}).DeriveWorkingKey(ipek, dukpt.AES128, dukpt.PINEncryption, dukpt.AES128, iksn, 5)
	if err != nil {
		t.Fatalf("derive working: %v", err)
	}
	assertHexEq(t, wk, vecWorkingKey)
}

func TestRSAKpSignVerify(t *testing.T) {
	msg := mustHex(t, "1234567890")
	sig, err := AsymSign(AlgoR2K, testLMK(t), vecRSASkLmk, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	assertHexEq(t, sig, vecRSASig)
	ok, err := Verify(AlgoR2K, mustHex(t, vecRSAPk), msg, sig)
	if err != nil || !ok {
		t.Fatalf("verify: %v ok=%v", err, ok)
	}
	// full round trip: generate, sign, verify
	pkDER, skLMK, err := GenKP(AlgoR2K, testLMK(t))
	if err != nil {
		t.Fatalf("genkp: %v", err)
	}
	sig2, err := AsymSign(AlgoR2K, testLMK(t), string(skLMK), msg)
	if err != nil {
		t.Fatalf("sign2: %v", err)
	}
	ok, err = Verify(AlgoR2K, pkDER, msg, sig2)
	if err != nil || !ok {
		t.Fatalf("verify2: %v ok=%v", err, ok)
	}
}

func TestECCKpSignVerify(t *testing.T) {
	msg := mustHex(t, "1234567890")
	// verify python-generated pk parses and a Go signature verifies
	pkDER := mustHex(t, vecECCPK)
	skLMK := vecECCSkLmk
	sig, err := AsymSign(AlgoECP256, testLMK(t), skLMK, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := Verify(AlgoECP256, pkDER, msg, sig)
	if err != nil || !ok {
		t.Fatalf("verify python pk: %v ok=%v", err, ok)
	}
	// full Go round trip
	gpk, gsk, err := GenKP(AlgoECP256, testLMK(t))
	if err != nil {
		t.Fatalf("genkp: %v", err)
	}
	gsig, err := AsymSign(AlgoECP256, testLMK(t), string(gsk), msg)
	if err != nil {
		t.Fatalf("gsign: %v", err)
	}
	ok, err = Verify(AlgoECP256, gpk, msg, gsig)
	if err != nil || !ok {
		t.Fatalf("gverify: %v ok=%v", err, ok)
	}
}

func TestECDH(t *testing.T) {
	derived, _, err := Ecdh(AlgoECP256, testLMK(t), vecECCSkLmk, mustHex(t, vecECCPK), mustHex(t, vecECCPK))
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	val, err := UnwrapKey(AlgoA128, testLMK(t), string(derived))
	if err != nil {
		t.Fatalf("unwrap derived: %v", err)
	}
	assertHexEq(t, val, vecEcdhVal)
}

func TestExpKeyStandaloneAndWrapped(t *testing.T) {
	// standalone: empty pk returns key blob untouched (port of the fix)
	out, err := ExpKey(AlgoA128, testLMK(t), []byte(vecAESBlob), nil, nil)
	if err != nil {
		t.Fatalf("exp standalone: %v", err)
	}
	if string(out) != vecAESBlob {
		t.Fatalf("standalone export should return key_lmk untouched")
	}
	// wrapped: rsa encrypt the clear key, then import back
	pk, sk, err := GenKP(AlgoR2K, testLMK(t))
	if err != nil {
		t.Fatalf("genkp: %v", err)
	}
	exp, err := ExpKey(AlgoA128, testLMK(t), []byte(vecAESBlob), nil, pk)
	if err != nil {
		t.Fatalf("exp wrapped: %v", err)
	}
	imp, err := ImpKey(AlgoR2K, testLMK(t), string(sk), AlgoA128, exp)
	if err != nil {
		t.Fatalf("imp: %v", err)
	}
	val, err := UnwrapKey(AlgoA128, testLMK(t), string(imp))
	if err != nil {
		t.Fatalf("unwrap imp: %v", err)
	}
	assertHexEq(t, val, vecAESKey)
}