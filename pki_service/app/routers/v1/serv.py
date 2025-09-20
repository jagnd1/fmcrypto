from fastapi import APIRouter, Depends
import httpx
from pki_service.app.schema.serv import CertCreateReq, CertResp, CertUpdate, \
    CrlMgmtReq, CrlMgmtResp
from pki_service.adapter.server_cli import ServerCli, get_client
from pki_service.usecase.serv import ServerUsecase

router = APIRouter()

def get_server_uc(client: httpx.AsyncClient = Depends(get_client)) -> ServerUsecase:
    server_cli = ServerCli(client)
    return ServerUsecase(server_cli)


@router.post("/cert", response_model=CertResp, status_code=200, 
             response_model_exclude_none=True)
async def create_cert(cert_obj: CertCreateReq, uc: ServerUsecase = Depends(get_server_uc)):
    cert_resp_obj = await uc.create_cert(cert_obj)
    return CertResp.model_validate(cert_resp_obj)

@router.put("/cert", response_model=CertResp, status_code=200, response_model_exclude_none=True)
async def renew_cert(cert_update_obj: CertUpdate, 
                     uc: ServerUsecase = Depends(get_server_uc)):
    cert_resp_obj = await uc.renew_cert(cert_update_obj)
    return CertResp.model_validate(cert_resp_obj)

@router.post("/crl", response_model=CrlMgmtResp, status_code=200,response_model_exclude_none=True)
async def crl_mgmt(crl_obj: CrlMgmtReq, uc: ServerUsecase = Depends(get_server_uc)):
    crl_resp_obj = await uc.crl_mgmt(crl_obj)
    return CrlMgmtResp.model_validate(crl_resp_obj)
