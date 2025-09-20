import asyncio
from common.utils.crypto import Utils
from pki_service.app.main import health_check
import pytest
import os
from crypto_service.app.routers.v1.crypto import (
    create_kp, data_decr, data_encr, ecdh, exp_key, exp_tr31, exp_tr34, gen_sign, ipek_derive, kcv_gen, 
    key_gen, mac, rand_gen, trans_pin, unwrap, wrap)
from crypto_service.app.schema.crypto import (
    DataDecrReq, DataEncrReq, EcdhReq, ExpKeyReq, ExpTr31Req, ExpTr34Req, IpekDeriveReq, KcvGenReq, KeyGenReq, 
    KpGenReq, MacReq, RandGenReq, SignReq, TransPinReq, UnwrapReq, WrapReq)
from crypto_service.usecase.crypto import CryptoUsecase
from crypto_service.usecase.hsm import HSMService


class TestCryptoRouter:

    def setup_method(self):
        hsm_type = os.getenv("CRYPTO_HSM", "GP")
        self.hsm_service = HSMService(hsm_type)
        self.hsm = self.hsm_service()
        self.crypto_usecase = CryptoUsecase(self.hsm)

    @pytest.mark.asyncio
    async def test_health(self):
        result = await health_check()
        print(f"res: {result}")
        assert result is not None

    async def _create_kp(self, algo: str, use_mode: str):
        kp_gen_req = KpGenReq(algo=algo, use_mode=use_mode)
        result = await create_kp(kp_gen_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"pk: {result.pk}")
            print(f"sk_lmk: {result.sk_lmk}")
            return result.pk, result.sk_lmk

    @pytest.mark.asyncio
    async def test_create_kp_ecp256(self):
        pk, sk_lmk = await self._create_kp("ECP256", "SIGN")
        assert pk is not None
        assert sk_lmk is not None
        assert len(pk) > 0
        assert len(sk_lmk) > 0

    @pytest.mark.asyncio
    async def test_create_kp_r2k(self):
        pk, sk_lmk = await self._create_kp("R2K", "ENCR")
        assert pk is not None
        assert sk_lmk is not None
        assert len(pk) > 0
        assert len(sk_lmk) > 0

    async def _gen_sign(self, algo: str, msg: str, sk_lmk: str):
        sign_req = SignReq(algo=algo, msg=msg, sk_lmk=sk_lmk)
        result = await gen_sign(sign_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"signature: {result.signature}")
            return result.signature

    @pytest.mark.asyncio
    async def test_gen_sign_ecp256(self):
        pk = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw_1V3KMih1tQcjlI2b-ay_h_V12EtgNbujDjIsDrmF_w-f8FsN4KY1r_80PBZ1nLKFNOjM66ez8DVP3GUS3-vQ=="
        sk_lmk = "RDAzMzZTMEVTMDBFMDAwMDAyODkwQjAxMzM5MzRGOUZBQjVDNjg0ODhCQjVBMzI3N0I0OUM3RTlGOTk1MDhEOUYyMzg3OTNFREJDQjlBNDlDN0E2NUE2OTQzM0QwMEJDMTVFRDcwNzMzRTI1OUNGRTBGNkMwNDgyMzhBMTVBOEUwODg0NDFDMTg3NzVDNDc5OEFBQjA2RUZDOEI2ODg3MEVGRkU1MjEyQTEzQzc1QkY5RUQ5NkExOEZENjMwM0I1NUIwNTA3Qjg5OEE3NzAzMEZBOTU2MUY4REExQTExRjEwQ0JGMDU2OEVEQUIwRTcwQjk3MUIyRDYyNjdBRUEwNkMzOUM3MzREQkFENDA1QkY2OENCMEUzMDc0MzAxMkRFNTA4NDQ4MTEzNEIzQkUzRDI5OTkwMTE1Q0QwMEZGNjE2RjE4OTlEMzQyOTBDNzVC"
        msg = "1234567890"
        signature = await self._gen_sign("ECP256", msg, sk_lmk)
        assert signature is not None
        assert len(signature) > 0
    
    @pytest.mark.asyncio
    async def test_gen_sign_r2k(self):
        pk = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkHb3rzuF6dBRfYDfyDt6y40bYbmx0s3Lgt1PuixLmOWLd1XMLG80aXroso24VTZ0d4GTXCFePb1GodeOMWdxUqUpUxxK8dHMAUls3ur4vFNNs4sNC2EX8JZkf7Z3WMS_oCFMQ_YHMwvYhdEJ8nuTkrUiLePmT4dJbJKVH3YFJk-n3cvHjXi4BLvQCKqpWw99Y18-veZnTxq4VtVXpoi5MocmrzragBwiUfoRcbz5yv2BtGm5_fXRUGAAoxxg5IM6_f1Z2AvQnEZRH5JeJa3Kb9J3DhKj9aZWHtn2omqBjGTdmio0QneSi2vWMkk0qbL3luFs0hcYKb9FJar2d9bdbwIDAQAB"
        sk_lmk = "RDI1MTJTMEVTMDBFMDAwMDYxQjA3RTZBNTQyNzdCOTMyRjU4MDRERTk3NzhBMzRFM0VDQjVGQjQ0OEYzRDI2ODRFMDhBMjYyNjkzMUY4MUFGQ0Q0NjY0NjA1QUJDMUQwRDhGNzI2QjYxOEE4MzhFODA2OUQyNDgyQjRBOTk0QUY1MzZEMzkxQTBEMEY5OUM0ODk3NDI0NUMwNEJCN0MzQ0NBNEE2QTZFMzNBQzM0Mjg0ODlBMEIxRUEyOTE4Q0ZDQzFERDZFQUZEMUZEOEQzMTg3ODEzMjU0OEI4MTdEQTdCQ0JENDMwQzY2NjA5RjgwODYyMEQwMzBDRDVCN0JCM0ZBMDNCMzU0Q0VFQTcwREI1Q0E3NDAzNDI5NzdCOEM0RjhEN0UxQUNCMTFEOTgzNjZCNDg4OTJEQjU5RDc2QTEwOEU1QTdEODUwRTNGNTEzNTNGMzJBRkNFN0JBQTk2NTM2RDU3NzM3Q0I4MTk3RUM4MzFBN0E3QjI0OTk4MUZERkI0NkNCNjk0OUQ3OTFEN0ZBQTQ3QjEzNDA1MkRFRTY4MEU0RjJDNEI2MTA3N0VEMTRDQ0I0NkRFRjhEODhBODVGNjQ2NEVGQTRFMzBCNkJGMkFDNjRBQzk4OTg2MkI4QTQ4MDBERUEwQTJERTQ2QTJBMzg3NzVEMzIxRDU0RjRFNzQ3MUY0MkRDMDEzRTRCMTM3ODQxMTJDN0JBNEM2QUMwQTBGMjUwNUQ3QjI5OTdDMUY1MjVGNUM5MjM2MUYyOUU3QURGRTFERjM2NkUyQzZFRUEwRDI1NkI3NDZEMjFENTVGMTYxNzAzQjI0RjRBNjQ2NkYwQzRBNjI5MzlEN0UxRDU1QTRFQ0E0NjUyRkQ2MzhFREE0MjM3MDQ4QkQyQ0ZFMzQwREYzQkREQkY3NjE3OTUzRTFDRjhENzEwODQ0QTMxNTI0MkMzM0E2OUFGRUQyRTg5MTQyRDE4MTU5QzM3RkI2RDdGNDREMTA0NDBEMEZGQTg4MTI1MjUxMDZGQUE0Q0U3NEUzODBDMjY1RDI2RTYzNkMxQzA4QUY3RTNERTNDMjNEQUY2NDdDMTRBNkM0RjFERjU5NDUwRTA1QjgwMDgzQjUzMDVFRkUwNTI3MDNGNjFGM0FBODNCRDUwQ0IwMjA1NjQxQzdDMUM3MjA5NzQzN0JEMzJEMjYwM0UzMTQ0NjNEQzUwMDY5OTkyNUFBNDI0NUZCNkRENTVFRTY4QTlFODVBRTRCRDM3Q0U0OTJGNDkzOTA1RTJDMDMzMTExQTE2MDUwM0NEMUY2QjE2ODAyQ0MwOTEzMjAwOTIyQ0JDOTVGMkYyRDg1RTdGRjBENkZGMEJDNzg5RUIyMzFFM0RCRDVGMjFGRTg2Q0NBQzIxQTY2ODEwNTQ5QzE5QkYxMjQwNEFEMTUyRTMyM0U2NDJCQkU0NEUxNTY1RDBCMURFRTlFNjlBMzIxQjcxNDkzNzNCRjIyMUQ0MzRBNEYyMDQ3MUJBMzMyNDRFQkRFRTMyMjgyOEVDODM5OUNFM0QzMURENzQwQzk5MTJEN0YwNEY0RTcxN0EwNjc2RkQwQUQ4QUI5QjhDM0U5Q0RGRTFDRjk2NTk5M0QzN0FEQzRDMDMyMkZCNzNENTg5RkFFQzJDQjIwOTJEREU3OUM4MDEwQ0Y0RUNFMDMwRDhEMDk1RjI5QTg1QkY2MEFFODQ2RDUyOTY3RUJDQjE2QjE5ODZDM0FBNkQ2OUYyMjE2MUQ5Q0JGRUE2RDg4RTgzQUZCRjg3Njg4OTkyRTU4RkEwQUExNzQwOEU0QTc1MTg4RUFBODhDODVDODcyNDYwNDI4RkVGNDBFNzJCODcxNTgzRkYzOUNENzY3NjcyQjE4QTY4ODJDMThCMERGNTJGRTIyQjRGNEZGRjZFQzk2QzEyQjVCQjA0MjY3MjJDNjcyMzA0ODY5MTg4OTU2NTgxQjc2RTZFQkY1NUFCQzgyOEU2NTdGRUNGRkUzREU2RjgzMTQ2QzdCODgxMUJBNkJFRTgzMTIwRjdFQTMyRkFGNkQ0QTkyM0E1NzdCMzQ2M0U0Q0MxMEVBOTk2QkVGODM3NDVGQjgzN0ZGQ0YzNDY4REQzOENGOTdENENBRjAyOTZCRUNBMTAyM0Y4NjYxMUMzRDFBRjhCOUM4RjI0NjVDMUI0NzBGOUYyN0U3MTBDMzlCNTMzNjZBODM1QkEyMEFDNkVFMDY3OTI0NkM3REY1OEU1OURBNkEzODdBQzUzOTE4Mjg1Mjc1QjQxQUM4OTc3MDZDMzk4RDNERTYxOUM4MkUyNEFDOTIxQjQ3MjNGRDdDRTQyMjA4OTEzRDMxQjY5NzAzQzYwODhEMTgxMzhERTk1MTNEMEZEQjcyMUE2M0VFRTk1RDRBRkZBRTIxMjJFRDBDRDRBRDk2MzQzOUFFODUyQjJBOTMzMTgxQTk3NTlBQUI2NTI0MzU2ODYwNTRCREMwMDkwNEI0QUNGQTZCMzdDNTU4ODhCRDhDMkFCQjc0MjQ2NTQ1RTE4NzlFRDUzNDhEQkREOTdEMzg3OUI1NjJDMjQ0RTQzMkU2M0NBMEU3NDgxMDhCRUU4Q0Q3NTUyQ0Q2Mjc5NTQxRkNFMTFCOTdCNUFGMzcyRjRBNkEyODcwQ0JBNjcyMUMzNERFRDJEMkRBQTUwQ0QyNzRBODVCNDNGQkNDMTNCNDdBQTI1MzhFRUVFRkU4MzMyMjA4NkRBN0Q2MjMzQ0RGNUY3QkQ2QkU5NEU2RjFBODExOTkxNzJGQjA0ODY4RDU0RDZCRkVEQjhCN0YzM0JBQkY5Q0I3RkE2REJCMDA4NDMwMDUwQTVCQjFCREM3OTJEOTZCQjA5QjQwNDgzM0E4MUM3OEQ5MTlCRDE5NkI4RjFBMURGQUMxMTMwMzY2Qjk0RjkzNjE3QTQ1NkQ0ODA5RkM3NjE4QzRCOTkzOURBMkFENDUwNzE3MDhGODNGODhDRTg4NEVDNUI1M0VDQUVDMEJFQTU0NzRGQTA5OURDNjg3MTAzRkE4NzUxMjhGNzFBMDVBREZFNkI5NTdDMEJGRUVGNTdDQjQ2OUUyQkVGNDE2NzYyN0Y4NTAwRDVEQUQ4RDAyMENCRTZCMDVGQkRBNTIwRTc0OUFERDEwM0NCNjM2MUI3RTBGQ0ZDQzQxRDI3OUUyMjk1MEM0Q0UzQkY4QzAwRTlERTYzNzA2RUJBRDIyRkFGQjU3QUQ0QTM2MjJFRTY3RDQ1NjBCNzE2NjY5Q0Y4RTNGODJBNjIxQjU0NTZGRDk1MjU2QTZBMjM4QUUyQkFEN0I4NjlBNzYzMTU3NzQwOTEwNTFGQjQ2MTNERDIxQjNBNTVCMw=="
        msg = "1234567890"
        signature = await self._gen_sign("R2K", msg, sk_lmk)
        assert signature is not None
        assert len(signature) > 0

    async def _ecdh(self, eph_pk: str, algo: str, key_type: str, use_mode: str):
        ecdh_req = EcdhReq(eph_pk=eph_pk, algo=algo, key_type=key_type, use_mode=use_mode)
        result = await ecdh(ecdh_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"derived_key: {result.derived_key}")
            print(f"kcv: {result.kcv}")
            print(f"recp_eph_pk: {result.recp_eph_pk}")
            return result.derived_key, result.kcv, result.recp_eph_pk

    @pytest.mark.asyncio
    async def test_ecdh(self):
        eph_pk = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw_1V3KMih1tQcjlI2b-ay_h_V12EtgNbujDjIsDrmF_w-f8FsN4KY1r_80PBZ1nLKFNOjM66ez8DVP3GUS3-vQ=="
        algo = "ECP256"
        key_type = "BDK"
        use_mode = "DERIV"
        derived_key, kcv, recp_eph_pk = await self._ecdh(eph_pk, algo, key_type, use_mode)
        assert derived_key is not None
        assert len(derived_key) > 0
        assert kcv is not None
        assert len(kcv) > 0
        assert recp_eph_pk is not None
        assert len(recp_eph_pk) > 0

    async def _exp_key(self, key_lmk: str, kcv: str, pk: str):
        exp_key_req = ExpKeyReq(key_lmk=key_lmk, kcv=kcv, pk=pk)
        result = await exp_key(exp_key_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"key_pk: {result.key_pk}")
            return result.key_pk

    @pytest.mark.asyncio
    async def test_exp_key(self):
        key_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        kcv = "62f55b"
        pk = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkHb3rzuF6dBRfYDfyDt6y40bYbmx0s3Lgt1PuixLmOWLd1XMLG80aXroso24VTZ0d4GTXCFePb1GodeOMWdxUqUpUxxK8dHMAUls3ur4vFNNs4sNC2EX8JZkf7Z3WMS_oCFMQ_YHMwvYhdEJ8nuTkrUiLePmT4dJbJKVH3YFJk-n3cvHjXi4BLvQCKqpWw99Y18-veZnTxq4VtVXpoi5MocmrzragBwiUfoRcbz5yv2BtGm5_fXRUGAAoxxg5IM6_f1Z2AvQnEZRH5JeJa3Kb9J3DhKj9aZWHtn2omqBjGTdmio0QneSi2vWMkk0qbL3luFs0hcYKb9FJar2d9bdbwIDAQAB"
        key_pk = await self._exp_key(key_lmk, kcv, pk)
        assert key_pk is not None
        assert len(key_pk) > 0
    
    async def _exp_tr31(self, key_lmk: str, zmk_lmk: str, iksn: str):
        exp_tr31_req = ExpTr31Req(key_lmk=key_lmk, zmk_lmk=zmk_lmk, iksn=iksn)
        result = await exp_tr31(exp_tr31_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"key_zmk: {result.key_zmk}")
            return result.key_zmk

    @pytest.mark.asyncio
    async def test_exp_tr31(self):
        key_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        zmk_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        iksn = "123456789012345600000000"
        key_zmk = await self._exp_tr31(key_lmk, zmk_lmk, iksn)
        assert key_zmk is not None
        assert len(key_zmk) > 0

    async def _rand_gen(self, len: str):
        rand_gen_req = RandGenReq(len=len)
        result = await rand_gen(rand_gen_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"rand no: {result.rand_no}")
            return result.rand_no

    @pytest.mark.asyncio
    async def test_rand_gen(self):
        lenlen = "12"
        rand_no_ = await self._rand_gen(lenlen)
        assert rand_no_ is not None
    
    async def _exp_tr34(self, kbpk: str, kdh_cert: str, krd_cert: str, kdh_sk_lmk: str, kcv: str):
        exp_tr34_req = ExpTr34Req(
            kbpk=kbpk, kdh_cert=kdh_cert, krd_cert=krd_cert, kdh_sk_lmk=kdh_sk_lmk, kcv=kcv)
        result = await exp_tr34(exp_tr34_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"ed: {result.ed}")
            return result.aa, result.ed, result.signature

    @pytest.mark.asyncio
    async def test_exp_tr34(self):
        kbpk = "RDAxMTJEMEFCMDBFMDAwMEI0MkUyMTY3QjI3ODE2QkQxOEQwN0EyODhGQUFENTUzREI4NjlBMTk4QThGQkNGMUQ4MTgyNEEwQjk3QTQzMkNEMkIwQkU5MTc3MEU4RTk2MzJDRUQwQzU3OEZBNTA5Rg=="
        kdh_cert = "MIIDajCCAlSgAwIBAgIIGGYC2wHUAZAwCwYJKoZIhvcNAQELMFAxCzAJBgNVBAYTAkVHMQ4wDAYDVQQIDAVDYWlybzEOMAwGA1UEBwwFQ2Fpcm8xDzANBgNVBAoMBlBheW1vYjEQMA4GA1UEAwwHUm9vdC1DQTAeFw0yNTA5MTcwNzU3MjRaFw0yNjA5MTcwNzU3MjRaMFAxCzAJBgNVBAYTAkVHMQ4wDAYDVQQIDAVDYWlybzEOMAwGA1UEBwwFQ2Fpcm8xDzANBgNVBAoMBlBheW1vYjEQMA4GA1UEAwwHUm9vdC1DQTCCASAwCwYJKoZIhvcNAQEBA4IBDwAwggEKAoIBAQDY79hCukfKDNejbRa6hTKMozdBWan7LrwYBU0P5np1aJpdjOj261Tr-PIWKFjE4ZfES-bwZykZWYGBWOw4b94ZULtFc9E98r08R8gYfl9aCUM04YVwJrTSZVGwQy7S0U73iHiaZa7jE5iqXBHbrM_fWv_txu_chLybb37aC9ofD_80-0cBqavT7ssYHFYGzmF5AK2X-oot2-Ekj28oqdcnshFJ6oGEkN1poD9Nrp1i2QjQB7UscjqkZQ3ONDXniQdF6RkvbOcTIjClfAlrncX9KNCFwa_xjVyBiKhYWs5lpJGFfr_e8e15uSC4aK434L6bRTRdHaKqhQYiJtUVNlw_AgMBAAGjTjBMMCkGA1UdDgQiBCALk1Ot-NUPYzG7YyJkFIE7kGnx3Wcip6EAsYMsIrjEwjAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBhjALBgkqhkiG9w0BAQsDggEBAFK6TaAORcwSnlG8az-bsC1oaLSEgrPTByJnsDB00kb0-8Qgj8mmddtxeRBCMXxPtubIIG39LD3oqdH46yWEMO7yWbiEoTQR4oZIhvn8p0f-DOgoyxJ3S86fD2_N5n-3S-SIa0eXtuc1r1iJxazQwDomlSW3sMTIvuKKugE9x3ytyT-vknAi-rm7m4gpFYDjpzJ34l4A3Fcyy3_kP0n4Aq4mxgyCC-8dVV3g6z5yL_ILwBAp5BfqFSy8xgN0qpE5n3luewDRjHELK_yNg3zOjzikeG9ADR-h9OyynDERb_l7-vc8EGfs4gUn9swx6cIrpeGGjiVZxfG6sMDsabYCziE="
        krd_cert = "MIIDajCCAlSgAwIBAgIIGGYC2wHUAZAwCwYJKoZIhvcNAQELMFAxCzAJBgNVBAYTAkVHMQ4wDAYDVQQIDAVDYWlybzEOMAwGA1UEBwwFQ2Fpcm8xDzANBgNVBAoMBlBheW1vYjEQMA4GA1UEAwwHUm9vdC1DQTAeFw0yNTA5MTcwNzU3MjRaFw0yNjA5MTcwNzU3MjRaMFAxCzAJBgNVBAYTAkVHMQ4wDAYDVQQIDAVDYWlybzEOMAwGA1UEBwwFQ2Fpcm8xDzANBgNVBAoMBlBheW1vYjEQMA4GA1UEAwwHUm9vdC1DQTCCASAwCwYJKoZIhvcNAQEBA4IBDwAwggEKAoIBAQDY79hCukfKDNejbRa6hTKMozdBWan7LrwYBU0P5np1aJpdjOj261Tr-PIWKFjE4ZfES-bwZykZWYGBWOw4b94ZULtFc9E98r08R8gYfl9aCUM04YVwJrTSZVGwQy7S0U73iHiaZa7jE5iqXBHbrM_fWv_txu_chLybb37aC9ofD_80-0cBqavT7ssYHFYGzmF5AK2X-oot2-Ekj28oqdcnshFJ6oGEkN1poD9Nrp1i2QjQB7UscjqkZQ3ONDXniQdF6RkvbOcTIjClfAlrncX9KNCFwa_xjVyBiKhYWs5lpJGFfr_e8e15uSC4aK434L6bRTRdHaKqhQYiJtUVNlw_AgMBAAGjTjBMMCkGA1UdDgQiBCALk1Ot-NUPYzG7YyJkFIE7kGnx3Wcip6EAsYMsIrjEwjAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBhjALBgkqhkiG9w0BAQsDggEBAFK6TaAORcwSnlG8az-bsC1oaLSEgrPTByJnsDB00kb0-8Qgj8mmddtxeRBCMXxPtubIIG39LD3oqdH46yWEMO7yWbiEoTQR4oZIhvn8p0f-DOgoyxJ3S86fD2_N5n-3S-SIa0eXtuc1r1iJxazQwDomlSW3sMTIvuKKugE9x3ytyT-vknAi-rm7m4gpFYDjpzJ34l4A3Fcyy3_kP0n4Aq4mxgyCC-8dVV3g6z5yL_ILwBAp5BfqFSy8xgN0qpE5n3luewDRjHELK_yNg3zOjzikeG9ADR-h9OyynDERb_l7-vc8EGfs4gUn9swx6cIrpeGGjiVZxfG6sMDsabYCziE="
        kdh_sk_lmk = "RDI1MTJTMEVTMDBFMDAwMDYxQjA3RTZBNTQyNzdCOTMyRjU4MDRERTk3NzhBMzRFM0VDQjVGQjQ0OEYzRDI2ODRFMDhBMjYyNjkzMUY4MUFGQ0Q0NjY0NjA1QUJDMUQwRDhGNzI2QjYxOEE4MzhFODA2OUQyNDgyQjRBOTk0QUY1MzZEMzkxQTBEMEY5OUM0ODk3NDI0NUMwNEJCN0MzQ0NBNEE2QTZFMzNBQzM0Mjg0ODlBMEIxRUEyOTE4Q0ZDQzFERDZFQUZEMUZEOEQzMTg3ODEzMjU0OEI4MTdEQTdCQ0JENDMwQzY2NjA5RjgwODYyMEQwMzBDRDVCN0JCM0ZBMDNCMzU0Q0VFQTcwREI1Q0E3NDAzNDI5NzdCOEM0RjhEN0UxQUNCMTFEOTgzNjZCNDg4OTJEQjU5RDc2QTEwOEU1QTdEODUwRTNGNTEzNTNGMzJBRkNFN0JBQTk2NTM2RDU3NzM3Q0I4MTk3RUM4MzFBN0E3QjI0OTk4MUZERkI0NkNCNjk0OUQ3OTFEN0ZBQTQ3QjEzNDA1MkRFRTY4MEU0RjJDNEI2MTA3N0VEMTRDQ0I0NkRFRjhEODhBODVGNjQ2NEVGQTRFMzBCNkJGMkFDNjRBQzk4OTg2MkI4QTQ4MDBERUEwQTJERTQ2QTJBMzg3NzVEMzIxRDU0RjRFNzQ3MUY0MkRDMDEzRTRCMTM3ODQxMTJDN0JBNEM2QUMwQTBGMjUwNUQ3QjI5OTdDMUY1MjVGNUM5MjM2MUYyOUU3QURGRTFERjM2NkUyQzZFRUEwRDI1NkI3NDZEMjFENTVGMTYxNzAzQjI0RjRBNjQ2NkYwQzRBNjI5MzlEN0UxRDU1QTRFQ0E0NjUyRkQ2MzhFREE0MjM3MDQ4QkQyQ0ZFMzQwREYzQkREQkY3NjE3OTUzRTFDRjhENzEwODQ0QTMxNTI0MkMzM0E2OUFGRUQyRTg5MTQyRDE4MTU5QzM3RkI2RDdGNDREMTA0NDBEMEZGQTg4MTI1MjUxMDZGQUE0Q0U3NEUzODBDMjY1RDI2RTYzNkMxQzA4QUY3RTNERTNDMjNEQUY2NDdDMTRBNkM0RjFERjU5NDUwRTA1QjgwMDgzQjUzMDVFRkUwNTI3MDNGNjFGM0FBODNCRDUwQ0IwMjA1NjQxQzdDMUM3MjA5NzQzN0JEMzJEMjYwM0UzMTQ0NjNEQzUwMDY5OTkyNUFBNDI0NUZCNkRENTVFRTY4QTlFODVBRTRCRDM3Q0U0OTJGNDkzOTA1RTJDMDMzMTExQTE2MDUwM0NEMUY2QjE2ODAyQ0MwOTEzMjAwOTIyQ0JDOTVGMkYyRDg1RTdGRjBENkZGMEJDNzg5RUIyMzFFM0RCRDVGMjFGRTg2Q0NBQzIxQTY2ODEwNTQ5QzE5QkYxMjQwNEFEMTUyRTMyM0U2NDJCQkU0NEUxNTY1RDBCMURFRTlFNjlBMzIxQjcxNDkzNzNCRjIyMUQ0MzRBNEYyMDQ3MUJBMzMyNDRFQkRFRTMyMjgyOEVDODM5OUNFM0QzMURENzQwQzk5MTJEN0YwNEY0RTcxN0EwNjc2RkQwQUQ4QUI5QjhDM0U5Q0RGRTFDRjk2NTk5M0QzN0FEQzRDMDMyMkZCNzNENTg5RkFFQzJDQjIwOTJEREU3OUM4MDEwQ0Y0RUNFMDMwRDhEMDk1RjI5QTg1QkY2MEFFODQ2RDUyOTY3RUJDQjE2QjE5ODZDM0FBNkQ2OUYyMjE2MUQ5Q0JGRUE2RDg4RTgzQUZCRjg3Njg4OTkyRTU4RkEwQUExNzQwOEU0QTc1MTg4RUFBODhDODVDODcyNDYwNDI4RkVGNDBFNzJCODcxNTgzRkYzOUNENzY3NjcyQjE4QTY4ODJDMThCMERGNTJGRTIyQjRGNEZGRjZFQzk2QzEyQjVCQjA0MjY3MjJDNjcyMzA0ODY5MTg4OTU2NTgxQjc2RTZFQkY1NUFCQzgyOEU2NTdGRUNGRkUzREU2RjgzMTQ2QzdCODgxMUJBNkJFRTgzMTIwRjdFQTMyRkFGNkQ0QTkyM0E1NzdCMzQ2M0U0Q0MxMEVBOTk2QkVGODM3NDVGQjgzN0ZGQ0YzNDY4REQzOENGOTdENENBRjAyOTZCRUNBMTAyM0Y4NjYxMUMzRDFBRjhCOUM4RjI0NjVDMUI0NzBGOUYyN0U3MTBDMzlCNTMzNjZBODM1QkEyMEFDNkVFMDY3OTI0NkM3REY1OEU1OURBNkEzODdBQzUzOTE4Mjg1Mjc1QjQxQUM4OTc3MDZDMzk4RDNERTYxOUM4MkUyNEFDOTIxQjQ3MjNGRDdDRTQyMjA4OTEzRDMxQjY5NzAzQzYwODhEMTgxMzhERTk1MTNEMEZEQjcyMUE2M0VFRTk1RDRBRkZBRTIxMjJFRDBDRDRBRDk2MzQzOUFFODUyQjJBOTMzMTgxQTk3NTlBQUI2NTI0MzU2ODYwNTRCREMwMDkwNEI0QUNGQTZCMzdDNTU4ODhCRDhDMkFCQjc0MjQ2NTQ1RTE4NzlFRDUzNDhEQkREOTdEMzg3OUI1NjJDMjQ0RTQzMkU2M0NBMEU3NDgxMDhCRUU4Q0Q3NTUyQ0Q2Mjc5NTQxRkNFMTFCOTdCNUFGMzcyRjRBNkEyODcwQ0JBNjcyMUMzNERFRDJEMkRBQTUwQ0QyNzRBODVCNDNGQkNDMTNCNDdBQTI1MzhFRUVFRkU4MzMyMjA4NkRBN0Q2MjMzQ0RGNUY3QkQ2QkU5NEU2RjFBODExOTkxNzJGQjA0ODY4RDU0RDZCRkVEQjhCN0YzM0JBQkY5Q0I3RkE2REJCMDA4NDMwMDUwQTVCQjFCREM3OTJEOTZCQjA5QjQwNDgzM0E4MUM3OEQ5MTlCRDE5NkI4RjFBMURGQUMxMTMwMzY2Qjk0RjkzNjE3QTQ1NkQ0ODA5RkM3NjE4QzRCOTkzOURBMkFENDUwNzE3MDhGODNGODhDRTg4NEVDNUI1M0VDQUVDMEJFQTU0NzRGQTA5OURDNjg3MTAzRkE4NzUxMjhGNzFBMDVBREZFNkI5NTdDMEJGRUVGNTdDQjQ2OUUyQkVGNDE2NzYyN0Y4NTAwRDVEQUQ4RDAyMENCRTZCMDVGQkRBNTIwRTc0OUFERDEwM0NCNjM2MUI3RTBGQ0ZDQzQxRDI3OUUyMjk1MEM0Q0UzQkY4QzAwRTlERTYzNzA2RUJBRDIyRkFGQjU3QUQ0QTM2MjJFRTY3RDQ1NjBCNzE2NjY5Q0Y4RTNGODJBNjIxQjU0NTZGRDk1MjU2QTZBMjM4QUUyQkFEN0I4NjlBNzYzMTU3NzQwOTEwNTFGQjQ2MTNERDIxQjNBNTVCMw=="
        kcv = "123456"
        _, ed, _ = await self._exp_tr34(kbpk, kdh_cert, krd_cert, kdh_sk_lmk, kcv)
        assert ed is not None
        assert len(ed) > 0

    async def _key_gen(self, key_type: str, use_mode: str, algo: str):
        key_gen_req = KeyGenReq(key_type=key_type, use_mode=use_mode, algo=algo)
        result = await key_gen(key_gen_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"key_lmk: {result.key_lmk}")
            print(f"kcv: {result.kcv}")
            return result.key_lmk, result.kcv

    @pytest.mark.asyncio
    async def test_key_gen(self):
        key_type = "BDK"
        use_mode = "DERIV"
        algo = "A128"
        key_lmk, kcv = await self._key_gen(key_type, use_mode, algo)
        assert key_lmk is not None
        assert len(key_lmk) > 0
        assert kcv is not None
        assert len(kcv) > 0
    
    async def _kcv_gen(self, key_lmk: str):
        kcv_gen_req = KcvGenReq(key_lmk=key_lmk)
        result = await kcv_gen(kcv_gen_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"kcv: {result.kcv}")
            return result.kcv

    @pytest.mark.asyncio
    async def test_kcv_gen(self):
        key_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        kcv = await self._kcv_gen(key_lmk)
        assert kcv is not None
        assert len(kcv) > 0

    async def _ipek_derive(self, bdk_lmk: str, iksn: str, algo: str, use_mode: str):
        ipek_derive_req = IpekDeriveReq(bdk_lmk=bdk_lmk, iksn=iksn, algo=algo, use_mode=use_mode)
        result = await ipek_derive(ipek_derive_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"ipek_lmk: {result.ipek_lmk}")
            print(f"kcv: {result.kcv}")
            return result.ipek_lmk, result.kcv
            
    @pytest.mark.asyncio
    async def test_ipek_derive(self):
        bdk_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        iksn = "123456789012345600000000"
        algo = "A128"
        use_mode = "DERIV"
        ipek_lmk, kcv = await self._ipek_derive(bdk_lmk, iksn, algo, use_mode)
        assert ipek_lmk is not None
        assert len(ipek_lmk) > 0
        assert kcv is not None
        assert len(kcv) > 0

    async def _data_encr(self, key_lmk: str, encr_mode: str, iv: str, msg: str, algo: str):
        data_encr_req = DataEncrReq(
            key_lmk=key_lmk, encr_mode=encr_mode, iv=iv, msg=msg, algo=algo)
        result = await data_encr(data_encr_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"encr_msg: {result.encr_msg}")
            return result.encr_msg

    @pytest.mark.asyncio
    async def test_data_encr(self):
        key_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        encr_mode = "CBC"
        iv = "1234567812345678"
        msg = "1234567812345678"
        algo = "A128"
        encr_msg = await self._data_encr(key_lmk, encr_mode, iv, msg, algo)
        assert encr_msg is not None
        assert len(encr_msg) > 0

    async def _data_decr(self, key_lmk: str, encr_mode: str, iv: str, encr_msg: str, algo: str):
        data_decr_req = DataDecrReq(
            key_lmk=key_lmk, encr_mode=encr_mode, iv=iv, encr_msg=encr_msg, algo=algo)
        result = await data_decr(data_decr_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"msg: {result.msg}")
            return result.msg

    @pytest.mark.asyncio
    async def test_data_decr(self):
        key_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        encr_mode = "CBC"
        iv = "1234567812345678"
        encr_msg = "a252f698cfddc8fdef524419b02ff72e"
        algo = "A128"
        msg = await self._data_decr(key_lmk, encr_mode, iv, encr_msg, algo)
        assert msg is not None
        assert len(msg) > 0
    
    async def _mac(self, key_lmk: str, mac_mode: str, msg: str):
        mac_req = MacReq(key_lmk=key_lmk, mac_mode=mac_mode, msg=msg)
        result = await mac(mac_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"mac_resp: {result.mac_resp}")
            return result.mac_resp
            
    @pytest.mark.asyncio
    async def test_mac(self):
        key_lmk = "RDAxMTJEMEFCMDBFMDAwMEQ0MkRFOEU5MjU4RjkyOTBDMTJDQUQwQjZEM0JCMDk0MjBDRkFBMTMwNTY3REExODUzMEU0MTM2MTJFQzA5MUYyM0JFMjg0RTNDQkYxOTFBNkM0NURERkY5RDJCQUExMg=="
        mac_mode = "GENERATE"
        msg = "1234567812345678"
        mac_resp = await self._mac(key_lmk, mac_mode, msg)
        assert mac_resp is not None
        assert len(mac_resp) > 0

    # TODO: mac verify

    async def _trans_pin(
        self, key_lmk: str, src_pinblk: str, dest_key: str, ksn: str, pan: str):
        trans_pin_req = TransPinReq(
            key_lmk=key_lmk, src_pinblk=src_pinblk, dest_key=dest_key, ksn=ksn, pan=pan)
        result = await trans_pin(trans_pin_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"dest_pinblk: {result.dest_pinblk}")
            return result.dest_pinblk

    @pytest.mark.asyncio
    async def test_trans_pin(self):
        key_lmk = "RDAxNDREMEFCMDBFMDAwMEFCOUEyM0UzMTFDNjdDMDlCNjdCRTQ4Mzk2RUZFMUVBOUVGRTdGNDc1QkU4N0I1QTM1MzdGRTU4MkNCQkNEN0VDNDRDQ0Y0RTQxNkUwOTYzMkVENUJBNDUzRjdEQ0MyNjU1NzcyM0FFRjY2Q0FCRDFGMDJEOThBQzMwODJFOTQx"
        src_pinblk = "2200d9fd5c940538949f1e6f7d14e676"
        dest_key = "RDAxMTJQMFRFMDBOMDAwMDIzRTlERTgwMTI0QzMyMTZEN0FBNzNEQjFDQ0U2NkYxN0ZBRjEwNDYxOUM3RDc4QTIzM0I3QjQyRjUyMUU2QzkxNzM0RkY3QjZCMUZFMTYzRDYxQzczNTE1QzY3ODMxNA=="
        ksn = "123456789012345600000005"
        pan = "4111111111111111"
        dest_pinblk = await self._trans_pin(key_lmk, src_pinblk, dest_key, ksn, pan)
        assert dest_pinblk is not None
        assert len(dest_pinblk) > 0

    async def _key_wrap(self, kbpk: str, key: str, algo: str):
        key_wrap_req = WrapReq(algo=algo, kbpk=kbpk, key=key)
        result = await wrap(key_wrap_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"key_kbpk: {result.key_kbpk}")
            return result.key_kbpk

    @pytest.mark.asyncio
    async def test_key_wrap(self):
        kbpk = "ZGZiOWJmMzQ4Y2MxMjk4NThjYjM3YzczNjI3ZjZiM2I="
        key = "MjM5MkY3RUZFMEZENjE3OTczMDE4NjgzNjczRUExNDM="
        algo = "A128"
        key_kbpk = await self._key_wrap(kbpk, key, algo)
        assert key_kbpk is not None
        assert len(key_kbpk) > 0

    async def _key_unwrap(self, key_kbpk: str, kbpk: str):
        key_unwrap_req = UnwrapReq(key_kbpk=key_kbpk, kbpk=kbpk)
        result = await unwrap(key_unwrap_req, self.crypto_usecase)
        if result and result.status == "success":
            print(f"key: {result.key}")
            return result.key

    @pytest.mark.asyncio
    async def test_key_unwrap(self):
        kbpk = "ZGZiOWJmMzQ4Y2MxMjk4NThjYjM3YzczNjI3ZjZiM2I="
        key_kbpk = "RDAxNDREMEFCMDBFMDAwMEE5OTg1MzE2Qzc5N0NGNTc4NDZBOEM3NDc4ODU1MTg3NTNFNEZEOUE3MzY1OTYwQTA0RDNERUY5OTcwREQ0MzFEQjhCQzVBNjg4MzE5REY5RDYwOEIxRDRCQTE2MEUwNDNDOTg2MUMwMkMyRkM1QTY1NDBCMTBGNzIwMTdBOEJG"
        key = await self._key_unwrap(key_kbpk, kbpk)
        assert key is not None
        assert len(key) > 0

if __name__ == "__main__":
    test_crypto_router = TestCryptoRouter()
    test_crypto_router.setup_method()  # Manually call setup for standalone execution
    asyncio.run(test_crypto_router.test_exp_tr34())