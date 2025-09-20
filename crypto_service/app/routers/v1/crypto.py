import os
from fastapi import APIRouter, Depends

from crypto_service.app.schema.crypto import (
    DataDecrReq, DataDecrResp, DataEncrReq, DataEncrResp, EcdhReq, EcdhResp, ExpKeyReq, ExpKeyResp, 
    ExpTr31Req, ExpTr31Resp, ExpTr34Req, ExpTr34Resp, IpekDeriveReq, IpekDeriveResp, KcvGenReq, 
    KcvGenResp, KeyGenReq, KeyGenResp, KpGenReq, KpGenResp, MacReq, MacResp, RandGenReq, 
    RandGenResp, SignReq, SignResp, TransPinReq, TransPinResp, UnwrapReq, UnwrapResp, WrapReq, 
    WrapResp)
from crypto_service.domain.models.hsm import HSM
from crypto_service.usecase.crypto import CryptoUsecase
from crypto_service.usecase.hsm import HSMService

hsm = os.getenv("CRYPTO_HSM", "GP")

router = APIRouter()

hsm_service = HSMService(hsm)

def get_crypto_usecase(hsm: HSM = Depends(hsm_service)) -> CryptoUsecase:
    crypto_usecase = CryptoUsecase(hsm)
    return crypto_usecase

@router.post("/kp_gen", response_model=KpGenResp, status_code=200, 
             response_model_exclude_none=True)
async def create_kp(kp_gen_obj: KpGenReq, 
                    crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    kp_gen_obj = await crypto_usecase.create_kp(kp_gen_obj)
    return KpGenResp.model_validate(kp_gen_obj)

@router.post("/gen_sign", response_model=SignResp, status_code=200, 
             response_model_exclude_none=True)
async def gen_sign(sign_req_obj: SignReq, 
                   crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    sign_resp_obj = await crypto_usecase.gen_sign(sign_req_obj)
    return SignResp.model_validate(sign_resp_obj)

@router.post("/ecdh", response_model=EcdhResp, status_code=200, 
             response_model_exclude_none=True)
async def ecdh(ecdh_req: EcdhReq, 
               crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    ecdh_resp = await crypto_usecase.ecdh(ecdh_req)
    return EcdhResp.model_validate(ecdh_resp)

@router.post("/exp_key", response_model=ExpKeyResp, status_code=200, 
             response_model_exclude_none=True)
async def exp_key(exp_key_req: ExpKeyReq, 
                  crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    exp_key_resp = await crypto_usecase.exp_key(exp_key_req)
    return ExpKeyResp.model_validate(exp_key_resp)

@router.post("/exp_tr31", response_model=ExpTr31Resp, status_code=200, 
             response_model_exclude_none=True)
async def exp_tr31(exp_tr31_req: ExpTr31Req, 
                   crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    exp_tr31_resp = await crypto_usecase.exp_tr31(exp_tr31_req)
    return ExpTr31Resp.model_validate(exp_tr31_resp)

@router.post("/rand_gen", response_model=RandGenResp, status_code=200, 
             response_model_exclude_none=True)
async def rand_gen(rand_gen_req: RandGenReq, 
                   crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    rand_gen_resp = await crypto_usecase.rand_gen(rand_gen_req)
    return RandGenResp.model_validate(rand_gen_resp)

@router.post("/exp_tr34", response_model=ExpTr34Resp, status_code=200, 
             response_model_exclude_none=True)
async def exp_tr34(exp_tr34_req: ExpTr34Req, 
                   crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    exp_tr34_resp = await crypto_usecase.exp_tr34(exp_tr34_req)
    return ExpTr34Resp.model_validate(exp_tr34_resp)

@router.post("/key_gen", response_model=KeyGenResp, status_code=200, 
             response_model_exclude_none=True)
async def key_gen(key_gen_req: KeyGenReq, 
                  crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    key_gen_resp = await crypto_usecase.key_gen(key_gen_req)
    return KeyGenResp.model_validate(key_gen_resp)

@router.post("/kcv_gen", response_model=KcvGenResp, status_code=200, 
             response_model_exclude_none=True)
async def kcv_gen(kcv_gen_req: KcvGenReq, 
                  crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    kcv_gen_resp = await crypto_usecase.kcv_gen(kcv_gen_req)
    return KcvGenResp.model_validate(kcv_gen_resp)

    
@router.post("/ipek_derive", response_model=IpekDeriveResp, status_code=200, 
             response_model_exclude_none=True)
async def ipek_derive(ipek_derive_obj: IpekDeriveReq, 
                      crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    ipek_derive_resp = await crypto_usecase.ipek_derive(ipek_derive_obj)
    return IpekDeriveResp.model_validate(ipek_derive_resp)

@router.post("/data_decr", response_model=DataDecrResp, status_code=200, 
             response_model_exclude_none=True)
async def data_decr(data_decr_req: DataDecrReq, 
                    crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    data_decr_resp = await crypto_usecase.data_decr(data_decr_req)
    return DataDecrResp.model_validate(data_decr_resp)

@router.post("/data_encr", response_model=DataEncrResp, status_code=200, 
             response_model_exclude_none=True)
async def data_encr(data_encr_req: DataEncrReq, 
                    crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    data_encr_resp = await crypto_usecase.data_encr(data_encr_req)
    return DataEncrResp.model_validate(data_encr_resp)

@router.post("/mac", response_model=MacResp, status_code=200, 
             response_model_exclude_none=True)
async def mac(mac_req: MacReq, 
              crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    mac_resp = await crypto_usecase.mac(mac_req)
    return MacResp.model_validate(mac_resp)

@router.post("/trans_pin", response_model=TransPinResp, status_code=200, 
             response_model_exclude_none=True)
async def trans_pin(trans_pin_req: TransPinReq, 
                    crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    trans_pin_resp = await crypto_usecase.trans_pin(trans_pin_req)
    return TransPinResp.model_validate(trans_pin_resp)

@router.post("/wrap", response_model=WrapResp, status_code=200, 
             response_model_exclude_none=True)
async def wrap(wrap_req: WrapReq, 
                    crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    wrap_resp = await crypto_usecase.wrap(wrap_req)
    return WrapResp.model_validate(wrap_resp)

@router.post("/unwrap", response_model=UnwrapResp, status_code=200, 
             response_model_exclude_none=True)
async def unwrap(unwrap_req: UnwrapReq, 
                    crypto_usecase: CryptoUsecase = Depends(get_crypto_usecase)):
    unwrap_resp = await crypto_usecase.unwrap(unwrap_req)
    return UnwrapResp.model_validate(unwrap_resp)
