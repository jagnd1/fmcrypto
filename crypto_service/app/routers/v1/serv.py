import os
from typing import Dict, Optional
from fastapi import APIRouter, Depends

from crypto_service.app.schema.serv import (
    CertCreateReq, CertResp, CertUpdate, CrlMgmtReq, CrlMgmtResp)
from crypto_service.usecase.serv import ServerUsecase
from crypto_service.usecase.crypto import CryptoUsecase
from crypto_service.usecase.hsm import HSMService
from crypto_service.domain.models.hsm import HSM
from common.middlewares.auth import get_current_user

router = APIRouter()

hsm_name = os.getenv("CRYPTO_HSM", "GP")
hsm_service = HSMService(hsm_name)

def get_crypto_uc(hsm: HSM = Depends(hsm_service)) -> CryptoUsecase:
    return CryptoUsecase(hsm)

def get_server_uc(crypto_uc: CryptoUsecase = Depends(get_crypto_uc)) -> ServerUsecase:
    return ServerUsecase(crypto_uc)

@router.post("/cert", response_model=CertResp, status_code=200, response_model_exclude_none=True)
async def create_cert(
    cert_obj: CertCreateReq,
    user: Optional[Dict] = Depends(get_current_user(["route:cert:create", "api:cert:create"], optional=True)),
    uc: ServerUsecase = Depends(get_server_uc)):
    cert_resp_obj = await uc.create_cert(cert_obj)
    return CertResp.model_validate(cert_resp_obj)

@router.put("/cert", response_model=CertResp, status_code=200, response_model_exclude_none=True)
async def renew_cert(
    cert_update_obj: CertUpdate,
    user: Optional[Dict] = Depends(get_current_user(["route:cert:update", "api:cert:update"], optional=True)),
    uc: ServerUsecase = Depends(get_server_uc)):
    cert_resp_obj = await uc.renew_cert(cert_update_obj)
    return CertResp.model_validate(cert_resp_obj)

@router.post("/crl", response_model=CrlMgmtResp, status_code=200, response_model_exclude_none=True)
async def crl_mgmt(
    crl_obj: CrlMgmtReq,
    user: Optional[Dict] = Depends(get_current_user(["route:crl:create", "api:crl:create"], optional=True)),
    uc: ServerUsecase = Depends(get_server_uc)):
    crl_resp_obj = await uc.crl_mgmt(crl_obj)
    return CrlMgmtResp.model_validate(crl_resp_obj)