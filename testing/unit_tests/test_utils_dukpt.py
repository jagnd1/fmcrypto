
# generate all the valid key types for a few transactions.
# also demonstrate the calculation of a AES PIN Block (Format 4)
from common.utils.sw.dukpt import Dukpt, KeyType, KeyUsage, aes_encrypt_ecb, load_initial_key, xor


def test_gen_all_keys():
    bdk = bytes.fromhex('FEDCBA9876543210F1F1F1F1F1F1F1F1')
    bk = KeyType._AES128
    initial_key_id = bytes.fromhex('1234567890123456')
    k = KeyType._AES128

    dukpt_obj = Dukpt()
    initial_key = dukpt_obj.derive_initial_key(bdk, bk, initial_key_id)
    print(f"initial key: {initial_key}")
    load_initial_key(initial_key, bk, initial_key_id)
    i = 5 # counter
    print(f"counter: {i}")
    key_kek  = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._KeyEncryptionKey, k, initial_key_id, i)
    key_pin  = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._PINEncryption, k, initial_key_id, i)
    key_macg = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._MessageAuthenticationGeneration, k, initial_key_id, i)
    key_macv = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._MessageAuthenticationVerification, k, initial_key_id, i)
    key_macb = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._MessageAuthenticationBothWays, k, initial_key_id, i)
    key_dee  = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._DataEncryptionEncrypt, k, initial_key_id, i)
    key_ded  = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._DataEncryptionDecrypt, k, initial_key_id, i)
    key_deb  = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._DataEncryptionBothWays, k, initial_key_id, i)
    key_kd   = dukpt_obj.host_derive_working_key(
        bdk, bk, KeyUsage._KeyDerivation, k, initial_key_id, i)

    print(f"derication key: {key_kek [0]}")
    print(f"kek derivation data: {key_kek [1]}")
    print(f"ke key: {key_kek [2]}")

    print(f"pe derivation data: {key_pin[1]}")
    print(f"pe key: {key_pin[2]}")

    print(f"mac gen derivation data: {key_macg[1]}")
    print(f"mac gen key: {key_macg[2]}")

    print(f"mac verif derivation data: {key_macv[1]}")
    print(f"mac verif key: {key_macv[2]}")

    print(f"mac both derivation data: {key_macb[1]}")
    print(f"mac both key: {key_macb[2]}")

    print(f"DE encrypt derivation data: {key_dee[1]}")
    print(f"DE encrypt key: {key_dee[2]}")

    print(f"DE decrypt derivation data: {key_ded[1]}")
    print(f"DE decrypt key: {key_ded[2]}")

    print(f"DE both derivation data: {key_deb[1]}")
    print(f"DE both key: {key_deb[2]}")

    print(f"key derivation derivation data: {key_kd[1]}")
    print(f"key derivation key: {key_kd[2]}")

def test_pin_block_gen():
    key_pin = bytes.fromhex("5bf3921163bab8920115ca5d67d1949e")
    print("calc aes pin block - format 4")
    print("pan = 4111111111111111")
    print("PIN = 1234")
    print("random no. = 2F69ADDE2E9E7ACE")
    print("plain text pin field: 441234AA  AAAAAAAA  2F69ADDE  2E9E7ACE")
    print("plain text pan field: 44111111  11111111  10000000  00000000")
    print(f"pek: {key_pin.hex()}")
    pin_field = [ 0x44, 0x12, 0x34, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x2F, 0x69, 0xAD, 0xDE, 0x2E, 0x9E, 0x7A, 0xCE ]
    pan_field = [ 0x44, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
    block_a = aes_encrypt_ecb(key_pin, pin_field)
    block_b = xor(block_a, pan_field)
    pin_block = aes_encrypt_ecb(key_pin, block_b)
    print(f"Intermediate Block A: {block_a.hex()}")
    print(f"Intermediate Block B: {block_b.hex()}")
    print(f"Encrypted PIN Block: {pin_block.hex()}")


def test_get_working_key():
    bdk = bytes.fromhex('FEDCBA9876543210F1F1F1F1F1F1F1F1')
    bdk_type = KeyType._AES128
    key_usage = KeyUsage._PINEncryption
    key_type = KeyType._AES128
    intial_key_id = bytes.fromhex('1234567890123456')
    counter = 0x00000005
    print(f"bdk: {bdk.hex()}")
    print(f"initial key id: {intial_key_id.hex()}")
    dukpt_obj = Dukpt()
    key_pin = dukpt_obj.host_derive_working_key(
        bdk, bdk_type, key_usage, key_type, intial_key_id, counter)
    print(f"working key: {key_pin[2].hex()}")
    return key_pin[2]

if __name__ == "__main__":
    test_pin_block_gen()