from enum import Enum
import logging
from typing import Union
from crypto_service.app.schema.crypto import (
    DataDecrReq, DataDecrResp, DataEncrReq, DataEncrResp, EcdhReq, EcdhResp, ExpKeyReq, ExpKeyResp, 
    ExpTr31Req, ExpTr31Resp, ExpTr34Req, ExpTr34Resp, IpekDeriveReq, IpekDeriveResp, KcvGenReq, 
    KcvGenResp, KeyGenReq, KeyGenResp, KpGenReq, KpGenResp, MacReq, MacResp, RandGenReq, 
    RandGenResp, SignReq, SignResp, TransPinReq, TransPinResp, UnwrapReq, UnwrapResp, WrapReq, 
    WrapResp)
from common.utils.enum.algo import Algo
from common.utils.enum.encr_mode import EncrMode
from crypto_service.app.utils.enum.key_type import KeyType
from crypto_service.app.utils.enum.mac_mode import MacMode
from crypto_service.app.utils.enum.use_mode import UseMode
from crypto_service.domain.models.hsm import HSM
from common.utils.crypto import Utils as NewUtils

logger = logging.getLogger(__name__)

class Status(Enum):
    SUCCESS = "success"
    ERROR = "error"

class CryptoUsecase:

    def __init__(self, hsm: HSM):
        self.hsm = hsm

    async def create_kp(self, kp_gen_obj: KpGenReq) -> KpGenResp:
        # convert input
        algo = Algo.get_str_algo(kp_gen_obj.algo)
        use_mode = UseMode.get_str_use_mode(kp_gen_obj.use_mode)
        kp_gen_obj = self.hsm.get_kp_gen(algo)
        # build and send
        req = kp_gen_obj.build(algo, use_mode)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse resp
        kp_gen_obj.parse(resp)
        # extract data
        pk, sk_lmk = kp_gen_obj.get_kp()
        pk = NewUtils.urlsafe_b64encode(pk)
        sk_lmk = NewUtils.urlsafe_b64encode(sk_lmk)
        # send resp
        return KpGenResp(status=Status.SUCCESS, pk=pk, sk_lmk=sk_lmk)
    

    async def gen_sign(self, sign_req_obj: SignReq) -> SignResp:
        # convert the input params
        algo = Algo.get_str_algo(sign_req_obj.algo)
        sk_lmk = NewUtils.urlsafe_b64decode(sign_req_obj.sk_lmk)
        msg = bytes.fromhex(sign_req_obj.msg)
        # build and send req
        gen_sign_obj = self.hsm.get_gen_sign()
        req = gen_sign_obj.build(algo, msg, sk_lmk)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp received
        gen_sign_obj.parse(resp)
        sign_data = gen_sign_obj.get_sign_data().hex()
        # send the resp
        return SignResp(status=Status.SUCCESS, signature=sign_data)
    

    def _import_pk(self, init_pk: bytes, algo: Algo, 
                   use_mode: UseMode) -> Union[bytes, None]:
        # build the req
        pk_imp_obj = self.hsm.get_pk_imp()
        req = pk_imp_obj.build(init_pk, algo, use_mode)
        # send 
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp
        pk_imp_obj.parse(resp)
        pk_lmk = pk_imp_obj.get_pk()
        # return the pk_lmk
        return pk_lmk

    async def ecdh(self, ecdh_req: EcdhReq) -> EcdhResp:
        # fetch the hsm invoked type
        # 2 parts: 1 import pk, 2 ecdh
        # conver the input params
        eph_pk = NewUtils.urlsafe_b64decode(ecdh_req.eph_pk)
        print(f"eph_pk: {eph_pk.hex()}")
        algo:Algo = Algo.get_str_algo(ecdh_req.algo)
        use_mode = UseMode.get_str_use_mode(ecdh_req.use_mode)
        key_type = KeyType.get_str_key_type(ecdh_req.key_type)
        if ecdh_req.shared_info is None:
            shared_info = b''
        else:
            shared_info = bytes.fromhex(ecdh_req.shared_info)
        init_pk = eph_pk
        # 2. ecdh exchange
        if init_pk:
            pk_lmk = eph_pk
            # build and send the req
            ecdh_obj = self.hsm.get_ecka_dh()
            req = ecdh_obj.build_recp_derive_shared(algo, pk_lmk, shared_info, key_type, use_mode)
            cli = self.hsm.get_client()
            resp = cli.exec(req)
            # parse the resp received
            ecdh_obj.parse_recp_derive_shared(resp)
            recp_deriv_key, _kcv, _recp_eph_pk = ecdh_obj.get_recp_derive()
            logger.info(f"derived key: {recp_deriv_key.hex()}")
            logger.info(f"recp pk: {_recp_eph_pk.hex()}")
            logger.info(f"kcv: {_kcv.hex()}")
            derived_key = NewUtils.urlsafe_b64encode(recp_deriv_key)
            recp_eph_pk = NewUtils.urlsafe_b64encode(_recp_eph_pk)
            kcv = _kcv.hex()
        # send the resp
        return EcdhResp(status=Status.SUCCESS, derived_key=derived_key, kcv=kcv,
                        recp_eph_pk=recp_eph_pk)


    async def exp_key(self, exp_key_req: ExpKeyReq) -> ExpKeyResp:
        # input params conversion
        key_lmk = (NewUtils.urlsafe_b64decode(exp_key_req.key_lmk))
        kcv = bytes.fromhex(exp_key_req.kcv)
        pk = (NewUtils.urlsafe_b64decode(exp_key_req.pk))
        # build and send req
        exp_key_obj = self.hsm.get_exp_key()
        req = exp_key_obj.build(key_lmk, kcv, pk)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the response received
        exp_key_obj.parse(resp)
        _key_pk, _ = exp_key_obj.get_enc_key()
        key_pk = NewUtils.urlsafe_b64encode(_key_pk)
        # send resp
        return ExpKeyResp(status=Status.SUCCESS, key_pk=key_pk)


    async def exp_tr31(self, exp_tr31_req: ExpTr31Req) -> ExpTr31Resp:
        # conver the input params
        key_lmk = (NewUtils.urlsafe_b64decode(exp_tr31_req.key_lmk))
        zmk_lmk = (NewUtils.urlsafe_b64decode(exp_tr31_req.zmk_lmk))
        iksn = b''
        if exp_tr31_req.iksn:
            iksn = exp_tr31_req.iksn.encode()
        # build and send req
        exp_tr31_obj = self.hsm.get_exp_tr31()
        req = exp_tr31_obj.build(zmk_lmk, key_lmk, iksn)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp
        exp_tr31_obj.parse(resp)
        _enc_key, _ = exp_tr31_obj.get_key()
        key_zmk = NewUtils.urlsafe_b64encode(_enc_key)
        # send the resp
        return ExpTr31Resp(status=Status.SUCCESS, key_zmk=key_zmk)
    

    async def rand_gen(self, rand_gen_req: RandGenReq) -> RandGenResp:
        # conver the req params
        rand_gen_obj = self.hsm.get_rand_gen()
        # build and send the req
        req = rand_gen_obj.build(int(rand_gen_req.len))
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp received
        rand_gen_obj.parse(resp)
        _rand_no = rand_gen_obj.get_random_no()
        # send the resp
        return RandGenResp(status=Status.SUCCESS, rand_no=_rand_no.hex())


    async def exp_tr34(self, exp_tr34_req: ExpTr34Req) -> ExpTr34Resp:
        kbpk_lmk = (NewUtils.urlsafe_b64decode(exp_tr34_req.kbpk))
        kdh_cert = (NewUtils.urlsafe_b64decode(exp_tr34_req.kdh_cert))
        krd_cert = (NewUtils.urlsafe_b64decode(exp_tr34_req.krd_cert))
        sk_lmk = (NewUtils.urlsafe_b64decode(exp_tr34_req.kdh_sk_lmk))
        kcv = bytes.fromhex(exp_tr34_req.kcv)
        exp_tr34_obj = self.hsm.get_exp_tr34()
        req = exp_tr34_obj.build(kbpk_lmk, kcv, kdh_cert, krd_cert, sk_lmk)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        exp_tr34_obj.parse(resp)
        _aa, _ed, _sign_data = exp_tr34_obj.get_tr34()
        return ExpTr34Resp(
            status=Status.SUCCESS, aa=_aa.hex(), ed=NewUtils.urlsafe_b64encode(_ed), 
            signature=_sign_data.hex())
    

    async def key_gen(self, key_gen_req: KeyGenReq) -> KeyGenResp:
        # input conversion
        algo = Algo.get_str_algo(key_gen_req.algo)
        use_mode = UseMode.get_str_use_mode(key_gen_req.use_mode)
        key_type = KeyType.get_str_key_type(key_gen_req.key_type)
        # build and send req
        key_gen_obj = self.hsm.get_key_gen()
        if key_gen_req.exp_key is None:
            _exp_key = b''
        req = key_gen_obj.build(key_type, use_mode, _exp_key, algo)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse resp
        key_gen_obj.parse(resp)
        _key_lmk, _kcv = key_gen_obj.get_key()
        key_lmk = NewUtils.urlsafe_b64encode(_key_lmk)
        return KeyGenResp(status=Status.SUCCESS, key_lmk=key_lmk, kcv=_kcv.hex())
    

    async def kcv_gen(self, kcv_gen_req: KcvGenReq) -> KcvGenResp:
        # convert the input params
        key_lmk = NewUtils.urlsafe_b64decode(kcv_gen_req.key_lmk)
        # build and send req
        kcv_gen_obj = self.hsm.get_kcv_gen()
        req = kcv_gen_obj.build(key_lmk)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp received
        kcv_gen_obj.parse(resp)
        _kcv = kcv_gen_obj.get_kcv()
        # send the resp
        return KcvGenResp(status=Status.SUCCESS, kcv=_kcv.hex())
    
    async def ipek_derive(self, ipek_derive_req: IpekDeriveReq) -> IpekDeriveResp:
        # convert the input
        bdk_lmk = ((NewUtils.urlsafe_b64decode(ipek_derive_req.bdk_lmk)).decode()).encode()
        iksn = bytes.fromhex(ipek_derive_req.iksn)
        if ipek_derive_req.tk:
            tk_lmk = ((NewUtils.urlsafe_b64decode(ipek_derive_req.tk)).decode()).encode()
        else:
            tk_lmk = b''
        algo = Algo.get_str_algo(ipek_derive_req.algo)
        use_mode = UseMode.get_str_use_mode(ipek_derive_req.use_mode)
        # build and send
        _ipek_derive_obj = self.hsm.get_ipek_derive()
        req = _ipek_derive_obj.build(bdk_lmk, iksn, tk_lmk, algo, use_mode)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse
        _ipek_derive_obj.parse(resp)
        _ipek_lmk, _ipek_tk, _kcv = _ipek_derive_obj.get_key()
        ipek_lmk = NewUtils.urlsafe_b64encode(_ipek_lmk)
        ipek_tk = NewUtils.urlsafe_b64encode(_ipek_tk)
        # send resp
        return IpekDeriveResp(
            status=Status.SUCCESS, ipek_lmk=ipek_lmk, ipek_tk=ipek_tk, kcv=_kcv.hex())


    async def data_decr(self, data_decr_req: DataDecrReq) -> DataDecrResp:
        # input conversion
        key_lmk = NewUtils.urlsafe_b64decode(data_decr_req.key_lmk)
        if data_decr_req.ksn is None:
            ksn = b''
        else:
            ksn = bytes.fromhex(data_decr_req.ksn)
        encr_mode = EncrMode.get_str_encr_mode(data_decr_req.encr_mode)
        encr_msg = bytes.fromhex(data_decr_req.encr_msg)
        algo = Algo.get_str_algo(data_decr_req.algo)        
        # build and send req
        decr_obj = self.hsm.get_data_decr()
        req = decr_obj.build(key_lmk, data_decr_req.iv, encr_msg, encr_mode, ksn, algo)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp received
        decr_obj.parse(resp)
        _decr_msg = decr_obj.get_msg()
        # send the resp
        return DataDecrResp(status=Status.SUCCESS, msg=_decr_msg.hex())


    async def data_encr(self, data_encr_req: DataEncrReq) -> DataEncrResp:
        # convert the inpur parameters
        key_lmk = NewUtils.urlsafe_b64decode(data_encr_req.key_lmk)
        if data_encr_req.ksn is None:
            ksn = b''
        else:
            ksn = bytes.fromhex(data_encr_req.ksn)
        encr_mode = EncrMode.get_str_encr_mode(data_encr_req.encr_mode)
        msg = bytes.fromhex(data_encr_req.msg)
        algo = Algo.get_str_algo(data_encr_req.algo)
        # build and send req
        data_encr_obj = self.hsm.get_data_encr()
        req = data_encr_obj.build(msg, key_lmk, encr_mode, data_encr_req.iv, ksn, algo)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse resp received
        data_encr_obj.parse(resp)
        _encr_msg = data_encr_obj.get_msg()
        # send resp
        return DataEncrResp(status=Status.SUCCESS, encr_msg=_encr_msg.hex())
    
    async def mac(self, mac_req: MacReq) -> MacResp:
        # convert the input params
        key_lmk = (NewUtils.urlsafe_b64decode(mac_req.key_lmk))
        if mac_req.ksn is None:
            ksn = b''
        else:
            ksn = bytes.fromhex(mac_req.ksn)
        if mac_req.mac_mode == "GENERATE":
            _mac = b''
        else:
            _mac = bytes.fromhex(mac_req.mac)
        msg = bytes.fromhex(mac_req.msg)
        mac_obj = self.hsm.get_mac()
        mac_mode = MacMode.get_str_mac_mode(mac_req.mac_mode)
        # build and send the req
        req = mac_obj.build(key_lmk, ksn, mac_mode, _mac, msg)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp received
        mac_obj.parse(resp)
        _mac_resp = mac_obj.get_mac()
        # send the resp
        return MacResp(status=Status.SUCCESS, mac_resp=_mac_resp.hex())
    
    async def trans_pin(self, trans_pin_req: TransPinReq) -> TransPinResp:
        # convert the input params
        key_lmk = (NewUtils.urlsafe_b64decode(trans_pin_req.key_lmk))
        ksn = b''
        if trans_pin_req.ksn:
            ksn = bytes.fromhex(trans_pin_req.ksn)
        src_pinblk = bytes.fromhex(trans_pin_req.src_pinblk)
        dest_key = (NewUtils.urlsafe_b64decode(trans_pin_req.dest_key))
        dest_ksn = b''
        if trans_pin_req.dest_ksn:
            dest_ksn = bytes.fromhex(trans_pin_req.dest_ksn)
        pan = trans_pin_req.pan.encode()
        # build and send req
        trans_pin_obj = self.hsm.get_trans_pin()
        cli = self.hsm.get_client()
        req = trans_pin_obj.build(key_lmk, dest_key, ksn, src_pinblk, pan, dest_ksn)
        resp = cli.exec(req)
        # parse the resp received
        trans_pin_obj.parse(resp)
        dest_pinblk = (trans_pin_obj.get_pinblk())
        # send the resp
        return TransPinResp(status=Status.SUCCESS, dest_pinblk=dest_pinblk)


    async def wrap(self, wrap_req: WrapReq) -> WrapResp:
        # convert the input params
        algo = Algo.get_str_algo(wrap_req.algo)
        header = wrap_req.header or None
        kbpk = NewUtils.urlsafe_b64decode(wrap_req.kbpk)
        key = NewUtils.urlsafe_b64decode(wrap_req.key)
        # build and send req
        wrap_key_obj = self.hsm.get_wrap_key()
        req = wrap_key_obj.build(algo, header, kbpk, key)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp received
        wrap_key_obj.parse(resp)
        _key_kbpk = wrap_key_obj.get_key().encode()
        key_kbpk = NewUtils.urlsafe_b64encode(_key_kbpk)
        # send the resp
        return WrapResp(key_kbpk=key_kbpk, status=Status.SUCCESS)


    async def unwrap(self, unwrap_req: UnwrapReq) -> UnwrapResp:
        # convert the input params
        kbpk = NewUtils.urlsafe_b64decode(unwrap_req.kbpk)
        key_kbpk = NewUtils.urlsafe_b64decode(unwrap_req.key_kbpk).decode()
        # build and send req
        unwrap_key_obj = self.hsm.get_unwrap_key()
        req = unwrap_key_obj.build(kbpk, key_kbpk)
        cli = self.hsm.get_client()
        resp = cli.exec(req)
        # parse the resp received
        unwrap_key_obj.parse(resp)
        _key = unwrap_key_obj.get_key()
        key = NewUtils.urlsafe_b64encode(_key)
        # send the resp
        return UnwrapResp(key=key, status=Status.SUCCESS)
