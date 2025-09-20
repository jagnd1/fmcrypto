"""
AES DUKPT (Derived Unique Key Per Transaction) Implementation

This implementation is based on the reference implementation provided by the
Accredited Standards Committee X9 (ASC X9) for ANSI X9.24-3-2017.

Reference Implementation Source:
- X9.24 Part 3 Test Vectors: https://x9.org/standards/x9-24-part-3-test-vectors/
- Python Source Code: https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Python-Source-20180129-1.pdf

Original X9 Disclaimer:
"The information is provided 'as is' without warranty of any kind. X9 does not accept 
any responsibility or liability for the accuracy, content, completeness, or reliability 
of the computer code and information contained on this page and website."

This implementation has been modified from the original X9 reference implementation
to integrate with the fmcrypto Service architecture and requirements.

Copyright (c) 2025 fmcrypto Service
"""

from Crypto.Cipher import AES
from enum import Enum

Debug = False
NUMREG = 32
MAX_WORK = 16

# convert a 32-bit integer to a list of bytes in big-endian order.  Used to convert counter values 
# to byte lists.
def int_to_bytes(x):
    return [((x >> i) & 0xff) for i in (24,16,8,0)]


# B.3.1. enumerations
class DerivationPurpose(Enum):
    _InitialKey = 0
    _DerivationOrWorkingKey = 1

class KeyType(Enum):
    _2TDEA = 0
    _3TDEA = 1
    _AES128 = 2
    _AES192 = 3
    _AES256 = 4

class KeyUsage(Enum):
    _KeyEncryptionKey = 0x0002
    _PINEncryption = 0x1000
    _MessageAuthenticationGeneration = 0x2000
    _MessageAuthenticationVerification = 0x2001
    _MessageAuthenticationBothWays = 0x2002
    _DataEncryptionEncrypt = 0x3000
    _DataEncryptionDecrypt = 0x3001
    _DataEncryptionBothWays = 0x3002
    _KeyDerivation = 0x8000
    _KeyDerivationInitialKey = 9

# count the number of 1 bits in a counter value.  readable, but not efficient.
def count_one_bits(x):
    bits = 0
    mask = 1 << (NUMREG-1)
    while mask > 0:
        if x & mask:
            bits = bits + 1
        mask = mask >> 1
    return bits

# B.3.2. key length function
# length of an algorithm's key, in bits.
def key_length(key_type):
    if ( key_type == KeyType._2TDEA):
        return 128
    if ( key_type == KeyType._3TDEA):
        return 192
    if ( key_type == KeyType._AES128):
        return 128
    if ( key_type == KeyType._AES192):
        return 192
    if ( key_type == KeyType._AES256):
        return 256
    assert False

# encrypt plaintext with key using AES.
def aes_encrypt_ecb(key, plaintext):
    # ECB mode is specifically required by the ANSI X9.24-3-2017 standard for DUKPT key derivation
    # this is not a security vulnerability in this context as it's used for key derivation - 
    # not data encryption
    # nosonar python:S5542 - AES ECB required for X9.24-3 standard compliance
    encobj = AES.new(bytes(key), AES.MODE_ECB) 
    result = encobj.encrypt(bytes(plaintext))
    return result

# compute the xor of two 128-bit numbers
def xor(a, b):
    result = bytearray(16)
    for i in range(0,16):
        result[i] = a[i] ^ b[i]
    return result

# B.4.1. derive key algorithm
# AES DUKPT key derivation function.    
def derive_key(derivation_key, key_type, derivation_data, _):
    L = key_length(key_type)
    n = -(-L // 128)

    result = bytearray(n*16)
    for i in range(1, n+1):
        derivation_data[1] = i
        result[(i-1)*16:i*16] = aes_encrypt_ecb(derivation_key, derivation_data)

    derived_key = result[0:(L//8)]
    return derived_key

def _set_key_usage(key_usage, derivation_data):
    if (key_usage == KeyUsage._KeyEncryptionKey):
        derivation_data[2:4] = [0,2]
    elif (key_usage == KeyUsage._PINEncryption):
        derivation_data[2:4] = [16,0]
    elif (key_usage == KeyUsage._MessageAuthenticationGeneration):
        derivation_data[2:4] = [32,0]
    elif (key_usage == KeyUsage._MessageAuthenticationVerification):
        derivation_data[2:4] = [32,1]
    elif (key_usage == KeyUsage._MessageAuthenticationBothWays):
        derivation_data[2:4] = [32,2]
    elif (key_usage == KeyUsage._DataEncryptionEncrypt):
        derivation_data[2:4] = [48,0]
    elif (key_usage == KeyUsage._DataEncryptionDecrypt):
        derivation_data[2:4] = [48,1]
    elif (key_usage == KeyUsage._DataEncryptionBothWays):
        derivation_data[2:4] = [48,2]
    elif (key_usage == KeyUsage._KeyDerivation):
        derivation_data[2:4] = [128,0]
    elif (key_usage == KeyUsage._KeyDerivationInitialKey):
        derivation_data[2:4] = [128,1]
    else:
        assert False

def _set_derived_key_type(derived_key_type, derivation_data):
    if (derived_key_type == KeyType._2TDEA):
        derivation_data[4:6] = [0,0]
    elif (derived_key_type == KeyType._3TDEA):
        derivation_data[4:6] = [0,1]
    elif (derived_key_type == KeyType._AES128):
        derivation_data[4:6] = [0,2]
    elif (derived_key_type == KeyType._AES192):
        derivation_data[4:6] = [0,3]
    elif (derived_key_type == KeyType._AES256):
        derivation_data[4:6] = [0,4]
    else:
        assert False


# B.4.3. create derivation data
# compute derivation data for an AES DUKPT key derivation operation.
def create_derivation_data(
    derivation_purpose, key_usage, derived_key_type, initial_key_id, counter):
    derivation_data = bytearray(16)
    derivation_data[0] = 1
    derivation_data[1] = 1
    # set key usage
    _set_key_usage(key_usage, derivation_data)
    # set derived key type
    _set_derived_key_type(derived_key_type, derivation_data)
    # set derivation purpose
    if (derivation_purpose == DerivationPurpose._InitialKey):
        derivation_data[8:16] = initial_key_id[0:8]
    elif (derivation_purpose == DerivationPurpose._DerivationOrWorkingKey):
        derivation_data[8:12] = initial_key_id[4:8]
        derivation_data[12:16] = int_to_bytes(counter)
    else:
        assert False
    return derivation_data


# B.6.3. processing routines
# load an initial key for computing terminal transaction keys in sequence.
def load_initial_key(initial_key, derive_key_type, initial_key_id):
    global NUMREG
    global g_intermediate_derivation_key_register
    global g_intermediate_derivation_key_in_use
    global g_current_key
    global g_device_id
    global g_counter
    global g_shift_register
    global g_derive_key_type
    # set intermediate derivation key register
    g_intermediate_derivation_key_register = [None]*NUMREG
    g_intermediate_derivation_key_in_use = [False]*NUMREG
    g_intermediate_derivation_key_register[0] = initial_key
    g_intermediate_derivation_key_in_use[0] = True
    g_device_id = initial_key_id
    g_counter = 0
    g_shift_register = 1
    g_current_key = 0
    g_derive_key_type = derive_key_type
    # update derivation keys
    update_derivation_keys(NUMREG-1, derive_key_type)
    g_counter = g_counter + 1


# B.6.3. generate working keys
# generate a transaction key from the intermediate derivation key registers, and update the state 
# to prepare for the next transaction.
def generate_working_keys(working_key_usage, working_key_type):
    global NUMREG
    global g_intermediate_derivation_key_register
    global g_intermediate_derivation_key_in_use
    global g_current_key
    global g_device_id
    global g_counter
    global g_shift_register
    global g_derive_key_type
    # set shift register
    set_shift_register()

    while not g_intermediate_derivation_key_in_use[g_current_key]:
        g_counter = g_counter + g_shift_register
        if g_counter > ((1 << NUMREG) - 1):
            # Counter overflow - cease operation as per X9.24-3 standard
            return False
        set_shift_register()
    # create derivation data
    derivation_data = create_derivation_data(
        DerivationPurpose._DerivationOrWorkingKey, working_key_usage, working_key_type, 
        g_device_id, g_counter)
    assert g_intermediate_derivation_key_in_use[g_current_key]
    working_key = derive_key(
        g_intermediate_derivation_key_register[g_current_key], working_key_type, derivation_data, 
        g_derive_key_type)
    
    update_state_for_next_transactio ()
    return working_key

# B.6.3. update state for next transaction
# move the counter forward, and derive new intermediate derivation keys for the next transaction.
def update_state_for_next_transactio ():
    global NUMREG
    global MAX_WORK
    global g_intermediate_derivation_key_register
    global g_intermediate_derivation_key_in_use
    global g_current_key
    global g_device_id
    global g_counter
    global g_shift_register
    global g_derive_key_type
    
    one_bits  = count_one_bits(g_counter)
    if one_bits  <= MAX_WORK:
        update_derivation_keys(g_current_key, g_derive_key_type)
        g_intermediate_derivation_key_register[g_current_key] = 0
        g_intermediate_derivation_key_in_use[g_current_key] = False
        g_counter = g_counter + 1
    else:
        g_intermediate_derivation_key_register[g_current_key] = 0
        g_intermediate_derivation_key_in_use[g_current_key] = False
        g_counter = g_counter + g_shift_register

    if g_counter > (1 << NUMREG) - 1:
        # Counter overflow - cease operation as per X9.24-3 standard
        return False
    else:
        return True

# B.6.3. update derivation keys
# update all the intermediate derivation key registers below a certain point.
# this is used to:
# 1. update all the intermediate derivation key registers below the shift register after computing 
# a transaction key.
# 2. update all the intermediate derivation key registers when an initial key is loaded.
def update_derivation_keys(start, derive_key_type):
    global NUMREG
    global g_intermediate_derivation_key_register
    global g_intermediate_derivation_key_in_use
    global g_current_key
    global g_device_id
    global g_counter
    global g_shift_register

    i = start
    j = 1 << start

    base_key = g_intermediate_derivation_key_register[g_current_key]
    while j != 0:
        derivation_data = create_derivation_data(
            DerivationPurpose._DerivationOrWorkingKey, KeyUsage._KeyDerivation, derive_key_type, 
            g_device_id, g_counter | j)
        assert g_intermediate_derivation_key_in_use[g_current_key]
        g_intermediate_derivation_key_register[i] = derive_key(
            base_key, derive_key_type, derivation_data, derive_key_type)
        g_intermediate_derivation_key_in_use[i] = True
        j = j >> 1
        i = i - 1
    return True

# B.6.3. set shift register
# set the shift register to the value of the rightmost '1' bit in the counter.
def set_shift_register():
    global NUMREG
    global g_intermediate_derivation_key_register
    global g_intermediate_derivation_key_in_use
    global g_current_key
    global g_device_id
    global g_counter
    global g_shift_register

    g_shift_register = 1
    g_current_key = 0

    ret = True
    if g_counter == 0:
        return ret

    while (g_shift_register & g_counter) == 0:
        g_shift_register = g_shift_register << 1
        g_current_key = g_current_key + 1

    return True

class Dukpt:
    # B.5. derive initial key
    # derive the initial key for a particular initial_key_id from a BDK.
    def derive_initial_key(self, bdk, key_type, initial_key_id):
        derivation_data = create_derivation_data(
            DerivationPurpose._InitialKey, KeyUsage._KeyDerivationInitialKey, key_type, 
            initial_key_id, 0)
        initial_key = derive_key(bdk, key_type, derivation_data, key_type)
        return initial_key

    def derive_working_key(
        self, initial_key, derive_key_type, working_key_usage, working_key_type, initial_key_id, 
        counter):
        mask = 0x80000000
        working_counter = 0
        derivation_key = initial_key

        while mask > 0:
            if (mask & counter) != 0:
                working_counter = working_counter | mask
                derivation_data = create_derivation_data(DerivationPurpose._DerivationOrWorkingKey, KeyUsage._KeyDerivation, derive_key_type, initial_key_id, working_counter)
                derivation_key = derive_key(derivation_key, derive_key_type, derivation_data, derive_key_type)
            mask = mask >> 1

        derivation_data = create_derivation_data(DerivationPurpose._DerivationOrWorkingKey, working_key_usage, working_key_type, initial_key_id, counter)
        working_key = derive_key(derivation_key, working_key_type, derivation_data, derive_key_type)

        return derivation_key, derivation_data, working_key

    # B.5. host derive working key
    # derive a working key for a particular transaction based on a initial_key_id and counter.
    def host_derive_working_key(
        self, bdk, derive_key_type, working_key_usage, working_key_type, initial_key_id, counter):
        initial_key = self.derive_initial_key(bdk, derive_key_type, initial_key_id)
        print(f"intial key: {initial_key.hex()}")
        
        derivation_key, derivation_data, working_key = self.derive_working_key(
            initial_key, derive_key_type, working_key_usage, working_key_type, initial_key_id, 
            counter)
        return derivation_key, derivation_data, working_key
    

