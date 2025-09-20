
import asyncio
import os
import pytest

from common.utils.enum import encr_mode
from crypto_service.adapter.gp.data_decr import DataDecr
from crypto_service.adapter.gp.data_encr import DataEncr
from crypto_service.adapter.gp.exp_key import ExpKey
from crypto_service.adapter.gp.exp_tr31 import ExpTr31
from crypto_service.adapter.gp.gen_sign import GenSign
from crypto_service.adapter.gp.ipek_derive import IpekDerive
from crypto_service.adapter.gp.kcv_gen import KcvGen
from crypto_service.adapter.gp.key_gen import KeyGen
from crypto_service.adapter.gp.kp_gen import KpGen
from crypto_service.adapter.gp.mac_impl import MacImpl
from crypto_service.adapter.gp.rand_gen import RandGen
from crypto_service.adapter.gp.unwrap_key import UnwrapKey
from crypto_service.adapter.gp.wrap_key import WrapKey
from crypto_service.app.schema.crypto import MacMode
import httpx
from common.utils.crypto import Utils
from crypto_service.app.utils.enum.key_type import KeyType
import psec
from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from common.utils.gp.asym_key import AsymKey
from common.utils.gp.sym_key import SymKey
from common.utils.gp.tr34 import Tr34
from common.utils.sw.dukpt import Dukpt, KeyUsage, KeyType as SwKeyType
from common.utils.sw.tr31 import Tr31
from crypto_service.adapter.gp.ecdh import Ecdh
from crypto_service.adapter.gp.trans_pin import TransPin
from crypto_service.app.utils.enum.use_mode import UseMode
from pki_service.adapter.crl_mgmt import CrlMgmt
from pki_service.adapter.csr_gen import csr_gen
from pki_service.adapter.server_cli import ServerCli


def test_data_decr():
    data_decr = DataDecr()
    key_lmk: bytes = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    iv = "1234567812345678"
    encr_msg: bytes = bytes.fromhex("a252f698cfddc8fdef524419b02ff72e")
    ksn: bytes = b''
    resp = data_decr.build(key_lmk, iv, encr_msg, EncrMode.CBC, ksn, Algo.A128)
    data_decr.parse(resp)
    decr_msg = data_decr.get_msg()
    print(f"decr msg: {decr_msg.hex()}")

def test_data_encr():
    data_encr = DataEncr()
    key_lmk: bytes = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    iv = "1234567812345678"
    msg: bytes = bytes.fromhex("1234567812345678")
    ksn: bytes = b''
    resp = data_encr.build(msg, key_lmk, EncrMode.CBC, iv, ksn, Algo.A128)
    data_encr.parse(resp)
    encr_msg = data_encr.get_msg()
    print(f"encr msg: {encr_msg.hex()}")

def test_ecdh():
    ecdh_obj = Ecdh()
    init_pk = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004df16bf66a18de01e5683dd1aa4c9e07e0064d1e978c28f1cc765696f0be1134afbadb3819c34295d66ecd694db9d8504b445b3e66190ab3e5e43a75e231379eb")
    resp = ecdh_obj.build_recp_derive_shared(Algo.ECP256, init_pk, b"", KeyType.DEK, UseMode.BOTH)
    ecdh_obj.parse_recp_derive_shared(resp)
    derived_key, kcv, recv_pk = ecdh_obj.get_recp_derive()
    print(f"derived key under lmk: {derived_key.hex()}")
    print(f"kcv: {kcv.hex()}")
    print(f"recv pk: {recv_pk.hex()}")

def test_exp_key():
    key_lmk = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    kcv = bytes.fromhex("62f55b")
    pk = Utils.urlsafe_b64decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkHb3rzuF6dBRfYDfyDt6y40bYbmx0s3Lgt1PuixLmOWLd1XMLG80aXroso24VTZ0d4GTXCFePb1GodeOMWdxUqUpUxxK8dHMAUls3ur4vFNNs4sNC2EX8JZkf7Z3WMS_oCFMQ_YHMwvYhdEJ8nuTkrUiLePmT4dJbJKVH3YFJk-n3cvHjXi4BLvQCKqpWw99Y18-veZnTxq4VtVXpoi5MocmrzragBwiUfoRcbz5yv2BtGm5_fXRUGAAoxxg5IM6_f1Z2AvQnEZRH5JeJa3Kb9J3DhKj9aZWHtn2omqBjGTdmio0QneSi2vWMkk0qbL3luFs0hcYKb9FJar2d9bdbwIDAQAB")
    exp_key = ExpKey()
    resp = exp_key.build(key_lmk, kcv, pk)
    exp_key.parse(resp)
    key_pk, _ = exp_key.get_enc_key()
    print(f"exported key: {key_pk.hex()}")

def test_exp_tr31():
    key_lmk = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    zmk_lmk = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    iksn = bytes.fromhex("123456789012345600000000")
    exp_tr31 = ExpTr31()
    resp = exp_tr31.build(zmk_lmk, key_lmk, iksn)
    exp_tr31.parse(resp)
    key_zmk, _ = exp_tr31.get_key()
    print(f"tr31 exported key: {key_zmk}")

def test_tr34():
    tr34_obj = Tr34()
    sym_algo = Algo.A128
    kn = tr34_obj.sym_key_obj.gen_key(sym_algo)
    print(f"kn lmk: {kn.hex()}")
    kn_clear = tr34_obj.sym_key_obj.get_key_val(sym_algo, kn)
    print(f"kn clear: {kn_clear.hex()}")
    # ed
    kdh_sign_cert = Utils.urlsafe_b64decode("MIIDajCCAlSgAwIBAgIIGGYC2wHUAZAwCwYJKoZIhvcNAQELMFAxCzAJBgNVBAYTAkVHMQ4wDAYDVQQIDAVDYWlybzEOMAwGA1UEBwwFQ2Fpcm8xDzANBgNVBAoMBlBheW1vYjEQMA4GA1UEAwwHUm9vdC1DQTAeFw0yNTA5MTcwNzU3MjRaFw0yNjA5MTcwNzU3MjRaMFAxCzAJBgNVBAYTAkVHMQ4wDAYDVQQIDAVDYWlybzEOMAwGA1UEBwwFQ2Fpcm8xDzANBgNVBAoMBlBheW1vYjEQMA4GA1UEAwwHUm9vdC1DQTCCASAwCwYJKoZIhvcNAQEBA4IBDwAwggEKAoIBAQDY79hCukfKDNejbRa6hTKMozdBWan7LrwYBU0P5np1aJpdjOj261Tr-PIWKFjE4ZfES-bwZykZWYGBWOw4b94ZULtFc9E98r08R8gYfl9aCUM04YVwJrTSZVGwQy7S0U73iHiaZa7jE5iqXBHbrM_fWv_txu_chLybb37aC9ofD_80-0cBqavT7ssYHFYGzmF5AK2X-oot2-Ekj28oqdcnshFJ6oGEkN1poD9Nrp1i2QjQB7UscjqkZQ3ONDXniQdF6RkvbOcTIjClfAlrncX9KNCFwa_xjVyBiKhYWs5lpJGFfr_e8e15uSC4aK434L6bRTRdHaKqhQYiJtUVNlw_AgMBAAGjTjBMMCkGA1UdDgQiBCALk1Ot-NUPYzG7YyJkFIE7kGnx3Wcip6EAsYMsIrjEwjAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBhjALBgkqhkiG9w0BAQsDggEBAFK6TaAORcwSnlG8az-bsC1oaLSEgrPTByJnsDB00kb0-8Qgj8mmddtxeRBCMXxPtubIIG39LD3oqdH46yWEMO7yWbiEoTQR4oZIhvn8p0f-DOgoyxJ3S86fD2_N5n-3S-SIa0eXtuc1r1iJxazQwDomlSW3sMTIvuKKugE9x3ytyT-vknAi-rm7m4gpFYDjpzJ34l4A3Fcyy3_kP0n4Aq4mxgyCC-8dVV3g6z5yL_ILwBAp5BfqFSy8xgN0qpE5n3luewDRjHELK_yNg3zOjzikeG9ADR-h9OyynDERb_l7-vc8EGfs4gUn9swx6cIrpeGGjiVZxfG6sMDsabYCziE=")
    krd_enc_cert = kdh_sign_cert
    ed_obj = tr34_obj.build_ed(krd_enc_cert, kn_clear, sym_algo)
    print(f"ed: {ed_obj.dump().hex()}")
    # sd
    digest_algo = "sha256"
    issuer_sk_lmk = Utils.urlsafe_b64decode("RDI1MTJTMEVTMDBFMDAwMDYxQjA3RTZBNTQyNzdCOTMyRjU4MDRERTk3NzhBMzRFM0VDQjVGQjQ0OEYzRDI2ODRFMDhBMjYyNjkzMUY4MUFGQ0Q0NjY0NjA1QUJDMUQwRDhGNzI2QjYxOEE4MzhFODA2OUQyNDgyQjRBOTk0QUY1MzZEMzkxQTBEMEY5OUM0ODk3NDI0NUMwNEJCN0MzQ0NBNEE2QTZFMzNBQzM0Mjg0ODlBMEIxRUEyOTE4Q0ZDQzFERDZFQUZEMUZEOEQzMTg3ODEzMjU0OEI4MTdEQTdCQ0JENDMwQzY2NjA5RjgwODYyMEQwMzBDRDVCN0JCM0ZBMDNCMzU0Q0VFQTcwREI1Q0E3NDAzNDI5NzdCOEM0RjhEN0UxQUNCMTFEOTgzNjZCNDg4OTJEQjU5RDc2QTEwOEU1QTdEODUwRTNGNTEzNTNGMzJBRkNFN0JBQTk2NTM2RDU3NzM3Q0I4MTk3RUM4MzFBN0E3QjI0OTk4MUZERkI0NkNCNjk0OUQ3OTFEN0ZBQTQ3QjEzNDA1MkRFRTY4MEU0RjJDNEI2MTA3N0VEMTRDQ0I0NkRFRjhEODhBODVGNjQ2NEVGQTRFMzBCNkJGMkFDNjRBQzk4OTg2MkI4QTQ4MDBERUEwQTJERTQ2QTJBMzg3NzVEMzIxRDU0RjRFNzQ3MUY0MkRDMDEzRTRCMTM3ODQxMTJDN0JBNEM2QUMwQTBGMjUwNUQ3QjI5OTdDMUY1MjVGNUM5MjM2MUYyOUU3QURGRTFERjM2NkUyQzZFRUEwRDI1NkI3NDZEMjFENTVGMTYxNzAzQjI0RjRBNjQ2NkYwQzRBNjI5MzlEN0UxRDU1QTRFQ0E0NjUyRkQ2MzhFREE0MjM3MDQ4QkQyQ0ZFMzQwREYzQkREQkY3NjE3OTUzRTFDRjhENzEwODQ0QTMxNTI0MkMzM0E2OUFGRUQyRTg5MTQyRDE4MTU5QzM3RkI2RDdGNDREMTA0NDBEMEZGQTg4MTI1MjUxMDZGQUE0Q0U3NEUzODBDMjY1RDI2RTYzNkMxQzA4QUY3RTNERTNDMjNEQUY2NDdDMTRBNkM0RjFERjU5NDUwRTA1QjgwMDgzQjUzMDVFRkUwNTI3MDNGNjFGM0FBODNCRDUwQ0IwMjA1NjQxQzdDMUM3MjA5NzQzN0JEMzJEMjYwM0UzMTQ0NjNEQzUwMDY5OTkyNUFBNDI0NUZCNkRENTVFRTY4QTlFODVBRTRCRDM3Q0U0OTJGNDkzOTA1RTJDMDMzMTExQTE2MDUwM0NEMUY2QjE2ODAyQ0MwOTEzMjAwOTIyQ0JDOTVGMkYyRDg1RTdGRjBENkZGMEJDNzg5RUIyMzFFM0RCRDVGMjFGRTg2Q0NBQzIxQTY2ODEwNTQ5QzE5QkYxMjQwNEFEMTUyRTMyM0U2NDJCQkU0NEUxNTY1RDBCMURFRTlFNjlBMzIxQjcxNDkzNzNCRjIyMUQ0MzRBNEYyMDQ3MUJBMzMyNDRFQkRFRTMyMjgyOEVDODM5OUNFM0QzMURENzQwQzk5MTJEN0YwNEY0RTcxN0EwNjc2RkQwQUQ4QUI5QjhDM0U5Q0RGRTFDRjk2NTk5M0QzN0FEQzRDMDMyMkZCNzNENTg5RkFFQzJDQjIwOTJEREU3OUM4MDEwQ0Y0RUNFMDMwRDhEMDk1RjI5QTg1QkY2MEFFODQ2RDUyOTY3RUJDQjE2QjE5ODZDM0FBNkQ2OUYyMjE2MUQ5Q0JGRUE2RDg4RTgzQUZCRjg3Njg4OTkyRTU4RkEwQUExNzQwOEU0QTc1MTg4RUFBODhDODVDODcyNDYwNDI4RkVGNDBFNzJCODcxNTgzRkYzOUNENzY3NjcyQjE4QTY4ODJDMThCMERGNTJGRTIyQjRGNEZGRjZFQzk2QzEyQjVCQjA0MjY3MjJDNjcyMzA0ODY5MTg4OTU2NTgxQjc2RTZFQkY1NUFCQzgyOEU2NTdGRUNGRkUzREU2RjgzMTQ2QzdCODgxMUJBNkJFRTgzMTIwRjdFQTMyRkFGNkQ0QTkyM0E1NzdCMzQ2M0U0Q0MxMEVBOTk2QkVGODM3NDVGQjgzN0ZGQ0YzNDY4REQzOENGOTdENENBRjAyOTZCRUNBMTAyM0Y4NjYxMUMzRDFBRjhCOUM4RjI0NjVDMUI0NzBGOUYyN0U3MTBDMzlCNTMzNjZBODM1QkEyMEFDNkVFMDY3OTI0NkM3REY1OEU1OURBNkEzODdBQzUzOTE4Mjg1Mjc1QjQxQUM4OTc3MDZDMzk4RDNERTYxOUM4MkUyNEFDOTIxQjQ3MjNGRDdDRTQyMjA4OTEzRDMxQjY5NzAzQzYwODhEMTgxMzhERTk1MTNEMEZEQjcyMUE2M0VFRTk1RDRBRkZBRTIxMjJFRDBDRDRBRDk2MzQzOUFFODUyQjJBOTMzMTgxQTk3NTlBQUI2NTI0MzU2ODYwNTRCREMwMDkwNEI0QUNGQTZCMzdDNTU4ODhCRDhDMkFCQjc0MjQ2NTQ1RTE4NzlFRDUzNDhEQkREOTdEMzg3OUI1NjJDMjQ0RTQzMkU2M0NBMEU3NDgxMDhCRUU4Q0Q3NTUyQ0Q2Mjc5NTQxRkNFMTFCOTdCNUFGMzcyRjRBNkEyODcwQ0JBNjcyMUMzNERFRDJEMkRBQTUwQ0QyNzRBODVCNDNGQkNDMTNCNDdBQTI1MzhFRUVFRkU4MzMyMjA4NkRBN0Q2MjMzQ0RGNUY3QkQ2QkU5NEU2RjFBODExOTkxNzJGQjA0ODY4RDU0RDZCRkVEQjhCN0YzM0JBQkY5Q0I3RkE2REJCMDA4NDMwMDUwQTVCQjFCREM3OTJEOTZCQjA5QjQwNDgzM0E4MUM3OEQ5MTlCRDE5NkI4RjFBMURGQUMxMTMwMzY2Qjk0RjkzNjE3QTQ1NkQ0ODA5RkM3NjE4QzRCOTkzOURBMkFENDUwNzE3MDhGODNGODhDRTg4NEVDNUI1M0VDQUVDMEJFQTU0NzRGQTA5OURDNjg3MTAzRkE4NzUxMjhGNzFBMDVBREZFNkI5NTdDMEJGRUVGNTdDQjQ2OUUyQkVGNDE2NzYyN0Y4NTAwRDVEQUQ4RDAyMENCRTZCMDVGQkRBNTIwRTc0OUFERDEwM0NCNjM2MUI3RTBGQ0ZDQzQxRDI3OUUyMjk1MEM0Q0UzQkY4QzAwRTlERTYzNzA2RUJBRDIyRkFGQjU3QUQ0QTM2MjJFRTY3RDQ1NjBCNzE2NjY5Q0Y4RTNGODJBNjIxQjU0NTZGRDk1MjU2QTZBMjM4QUUyQkFEN0I4NjlBNzYzMTU3NzQwOTEwNTFGQjQ2MTNERDIxQjNBNTVCMw==")
    sd = tr34_obj.build_sd(digest_algo, ed_obj, kdh_sign_cert, issuer_sk_lmk)
    print(f"sd: {sd.hex()}")

def test_gen_sign():
    # pk = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw_1V3KMih1tQcjlI2b-ay_h_V12EtgNbujDjIsDrmF_w-f8FsN4KY1r_80PBZ1nLKFNOjM66ez8DVP3GUS3-vQ=="
    sk_lmk = Utils.urlsafe_b64decode("RDAzMzZTMEVTMDBFMDAwMDAyODkwQjAxMzM5MzRGOUZBQjVDNjg0ODhCQjVBMzI3N0I0OUM3RTlGOTk1MDhEOUYyMzg3OTNFREJDQjlBNDlDN0E2NUE2OTQzM0QwMEJDMTVFRDcwNzMzRTI1OUNGRTBGNkMwNDgyMzhBMTVBOEUwODg0NDFDMTg3NzVDNDc5OEFBQjA2RUZDOEI2ODg3MEVGRkU1MjEyQTEzQzc1QkY5RUQ5NkExOEZENjMwM0I1NUIwNTA3Qjg5OEE3NzAzMEZBOTU2MUY4REExQTExRjEwQ0JGMDU2OEVEQUIwRTcwQjk3MUIyRDYyNjdBRUEwNkMzOUM3MzREQkFENDA1QkY2OENCMEUzMDc0MzAxMkRFNTA4NDQ4MTEzNEIzQkUzRDI5OTkwMTE1Q0QwMEZGNjE2RjE4OTlEMzQyOTBDNzVC")
    msg = bytes.fromhex("1234567890")
    gen_sign = GenSign()
    resp = gen_sign.build(Algo.ECP256, msg, sk_lmk)
    gen_sign.parse(resp)
    sign = gen_sign.get_sign_data()
    print(f"signature: {sign.hex()}")

def test_ipek_derive():
    bdk_lmk = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    iksn = bytes.fromhex("123456789012345600000000")
    tk = b""
    ipek_derive = IpekDerive()
    resp = ipek_derive.build(bdk_lmk, iksn, tk, Algo.A128, UseMode.DERIV)
    ipek_derive.parse(resp)
    ipek_lmk, _, kcv = ipek_derive.get_key()
    print(f"ipek lmk: {ipek_lmk.hex()}")
    print(f"kcv: {kcv.hex()}")

def test_kcv_gen():
    key_lmk = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    kcv_gen = KcvGen()
    resp = kcv_gen.build(key_lmk)
    kcv_gen.parse(resp)
    kcv = kcv_gen.get_kcv()
    print(f"kcv: {kcv.hex()}")

def test_key_gen():
    key_gen = KeyGen()
    resp = key_gen.build(KeyType.BDK, UseMode.DERIV, b'', Algo.A128)
    key_gen.parse(resp)
    key_lmk, _ = key_gen.get_key()
    print(f"key lmk: {key_lmk}")

def _kp_gen(algo: Algo, use_mode: UseMode):
    kp_gen = KpGen()
    resp = kp_gen.build(algo, UseMode.SIGN)
    kp_gen.parse(resp)
    pk, sk_lmk = kp_gen.get_kp()
    if pk and sk_lmk:
        print(f"pk: {pk.hex()}")
        print(f"sk_lmk: {sk_lmk.hex()}")
        return pk, sk_lmk

def test_kp_gen_r2k():
    pk, sk_lmk = _kp_gen(Algo.R2K, UseMode.BOTH)
    assert pk
    assert sk_lmk
    assert len(pk) > 0
    assert len(sk_lmk) > 0

def test_kp_gen_ecp256():
    pk, sk_lmk = _kp_gen(Algo.ECP256, UseMode.SIGN)
    assert pk
    assert sk_lmk
    assert len(pk) > 0
    assert len(sk_lmk) > 0

    print(f"pk: {pk.hex()}")
    print(f"sk_lmk: {sk_lmk.hex()}")

def test_mac():
    key_lmk = Utils.urlsafe_b64decode("RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg==")
    ksn = bytes.fromhex("123456789012345600000000")
    mac_impl = MacImpl()
    msg = bytes.fromhex("1234567890")
    resp = mac_impl.build(key_lmk, ksn, MacMode.GENERATE, b'', msg)
    mac_impl.parse(resp)
    mac = mac_impl.get_mac()
    print(f"mac: {mac.hex()}")


def test_rand_gen():
    rand_gen = RandGen()
    resp = rand_gen.build(10)
    rand_gen.parse(resp)
    rand_no = rand_gen.get_random_no()
    print(f"rand no.: {rand_no.hex()}")

def test_pin_trans():
    trans_pin_obj = TransPin()
    ipek_lmk = Utils.urlsafe_b64decode("RDAxNDREMEFCMDBFMDAwMEFCOUEyM0UzMTFDNjdDMDlCNjdCRTQ4Mzk2RUZFMUVBOUVGRTdGNDc1QkU4N0I1QTM1MzdGRTU4MkNCQkNEN0VDNDRDQ0Y0RTQxNkUwOTYzMkVENUJBNDUzRjdEQ0MyNjU1NzcyM0FFRjY2Q0FCRDFGMDJEOThBQzMwODJFOTQx")
    src_pinblk = bytes.fromhex("2200d9fd5c940538949f1e6f7d14e676")
    zpk_lmk = Utils.urlsafe_b64decode("RDAxMTJQMFRFMDBOMDAwMDIzRTlERTgwMTI0QzMyMTZEN0FBNzNEQjFDQ0U2NkYxN0ZBRjEwNDYxOUM3RDc4QTIzM0I3QjQyRjUyMUU2QzkxNzM0RkY3QjZCMUZFMTYzRDYxQzczNTE1QzY3ODMxNA==")
    ksn = bytes.fromhex("123456789012345600000005")
    pan = b"4111111111111111"
    dest_pinblk = trans_pin_obj.build(ipek_lmk, zpk_lmk, ksn, src_pinblk, pan)
    print(f"dest pinblk: {dest_pinblk.hex()}")

def test_wrap_key():
    wrap_key = WrapKey()
    kbpk = Utils.urlsafe_b64decode("ZGZiOWJmMzQ4Y2MxMjk4NThjYjM3YzczNjI3ZjZiM2I=")
    key = Utils.urlsafe_b64decode("MjM5MkY3RUZFMEZENjE3OTczMDE4NjgzNjczRUExNDM=")
    algo = "A128"
    header = "DD0AB00E"
    resp = wrap_key.build(Algo.A128, header, kbpk, key)
    wrap_key.parse(resp)
    key_kbpk = wrap_key.get_key()
    print(f"key under kbpk: {key_kbpk}")

def test_unwrap_key():
    kbpk = Utils.urlsafe_b64decode("ZGZiOWJmMzQ4Y2MxMjk4NThjYjM3YzczNjI3ZjZiM2I=")
    key_kbpk = "D0144D0AB00E00006F858A454BC64185AFEEE6AE4D0CF81669B97DE9DCA24C02B5073292B51B6F259F9B53774B34FE58A9D6B6882D32F92C5F3208BD513E7F8DBB1064AAFF05402D"
    unwrap_key = UnwrapKey()
    resp = unwrap_key.build(kbpk, key_kbpk)
    unwrap_key.parse(resp)
    key = unwrap_key.get_key()
    print(f"unwrapped key: {key}")


def test_pinblk_iso0():
    pin_clear = "1234"
    pan = bytes.fromhex("5546123412341232")
    pin_blk_clear = psec.pinblock.encode_pinblock_iso_0(pin_clear, pan.hex())
    print(f"pinblk clear iso 0: {pin_blk_clear.hex()}")


def test_pinblk_iso4():
    sym_key_obj = SymKey()
    key = bytes.fromhex("443031343444304142303045303030304142394132334533313143363743303942363742453438333936454645314541394546453746343735424538374235413335333746453538324342424344374543343443434634453431364530393633324544354241343533463744434332363535373732334145463636434142443146303244393841433330383245393431")
    ksn = bytes.fromhex("123456789012345600000005")
    # 1. decrypt the ipek_lmk
    print(f"ipek_lmk: {key.hex()}")
    ipek_clear = sym_key_obj.get_key_val(Algo.A128, key)
    print(f"ipek clear: {ipek_clear.hex()}")
    # 1.1. extract intitial key id and counter from ksn
    initial_key_id = ksn[:8]
    print(f"initial key id: {initial_key_id.hex()}")
    counter = int(ksn[9:].hex())
    print(f"counter: {ksn[9:].hex()}")
    # 1.2. derive working key from ipek and initial key id and counter
    dukpt_obj = Dukpt()
    _, _, wk_clear = dukpt_obj.derive_working_key(
        ipek_clear, SwKeyType._AES128, KeyUsage._PINEncryption, SwKeyType._AES128, initial_key_id, 
        counter)
    print(f"working key clear: {wk_clear.hex()}")
    # 2. decrypt the source pin block
    wk_lmk = sym_key_obj.set_key_val(Algo.A128, wk_clear)
    print(f"working key under lmk: {wk_lmk.hex()}")
    pan = "5546123412341232"
    pin = "1234"
    pinblk = psec.pinblock.encipher_pinblock_iso_4(wk_clear, pin, pan)    
    print(f"encr pinblk: {pinblk.hex()}")


@pytest.mark.asyncio
async def test_csr_gen():
    rootca_sub = {
        'country': 'IN', 'state': 'KA', 'locale': 'BLR', 'org': 'FM', 'cn': 'Root-CA',}
    cli = httpx.AsyncClient(timeout=None)
    server_cli = ServerCli(cli)
    await csr_gen(server_cli, "ECP521", rootca_sub)
    

def test_asym_key():
    # test key creation
    asym_key_obj = AsymKey()
    algo = Algo.R2K
    pk, sk_lmk = asym_key_obj.gen_kp(algo)
    msg = b"this is clear msg"
    # test encr and decr
    if algo in [Algo.R2K, Algo.R3K, Algo.R4K]:
        encr_msg = asym_key_obj.asym_encrypt(algo, pk, msg)
        print(f"encr msg: {encr_msg.hex()}")
        decr_msg = asym_key_obj.asym_decrypt(algo, sk_lmk, encr_msg)
        print(f"decr msg: {decr_msg.decode('utf-8')}")
    # test sign and verification
    signature = asym_key_obj.sign(algo, sk_lmk, msg)
    print(f"sign: {signature.hex()}")
    ret = asym_key_obj.verify(algo, pk, msg, signature)
    print(f"verify: {ret}")
    # test key import and export
    sym_key_obj = SymKey()
    sym_algo = Algo.A128
    key_lmk = sym_key_obj.gen_key(sym_algo)
    print(f"key: {key_lmk.hex()}")
    key_pk = asym_key_obj.exp_key(algo, pk, sym_algo, key_lmk)
    print(f"exp key: {key_pk.hex()}")
    key_lmk = asym_key_obj.imp_key(algo, sk_lmk, sym_algo, key_pk)
    print(f"imp key: {key_lmk.hex()}")
    # test ecdh
    algo = Algo.ECP256
    pk, sk_lmk = asym_key_obj.gen_kp(algo)
    derived_key, pk_lmk = asym_key_obj.ecdh(algo, sk_lmk, pk, pk)
    print(f"derived key: {derived_key.hex()}")
    print(f"pk lmk: {pk_lmk.hex()}")


def test_tr31_asym():
    tr31_obj = Tr31()
    kbpk = bytes.fromhex("dfb9bf348cc129858cb37c73627f6b3b")
    sk = bytes.fromhex("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e6cb5bdd80aa45ae9c95e8c15476679ffec953c16851e711e743939589c64fc1a14403420004422548f88fb782ffb5eca3744452c72a1e558fbd6f73be5e48e93232cc45c5b16c4cd10c4cb8d5b8a17139e94882c8992572993425f41419ab7e90a42a494272")
    tr31_blob = tr31_obj.wrap(kbpk=kbpk, key=sk, header=tr31_obj.asym_header)
    print(f"tr31 blob: {tr31_blob}")
    print(f"tr31 blob b64 urlsafe: {Utils.urlsafe_b64encode(tr31_blob.encode())}")
    _sk = tr31_obj.unwrap(kbpk, tr31_blob)
    print(f"unwrap: {_sk.hex()}")


def test_tr31_sym():
    kbpk = bytes.fromhex("dfb9bf348cc129858cb37c73627f6b3b")
    key = bytes.fromhex("2392F7EFE0FD617973018683673EA143")
    tr31_obj = Tr31()
    tr31_blob = tr31_obj.wrap(kbpk, key)
    print(f"tr31 blob: {tr31_blob}")
    key = tr31_obj.unwrap(kbpk, tr31_blob)
    print(f"unwrapped key: {key.hex()}")

def test_symkey():
    sym_key = SymKey()
    sym_key._get_lmk()
    in_algo = Algo.A128
    key_lmk = sym_key.gen_key(in_algo)
    print(f"key_lmk: {key_lmk}")
    msg = b"this is the clear msg"
    iv = os.urandom(16)
    encr_msg = sym_key.encrypt(in_algo, EncrMode.CBC, key_lmk, iv, msg)
    print(f"encr msg: {encr_msg.hex()}")
    decr_msg = sym_key.decrypt(in_algo, EncrMode.CBC, key_lmk, iv, encr_msg)
    print(f"decr msg: {decr_msg.decode('utf-8')}")
    sign_msg = sym_key.sign(in_algo, key_lmk, msg)
    print(f"sign: {sign_msg.hex()}")

if __name__ == "__main__":
    test_tr34()