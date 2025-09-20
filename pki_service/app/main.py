
from contextlib import asynccontextmanager
import logging
import os
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from common.logging_config import setup_logging
from common.middlewares.reqid_exception import ReqIDExceptionMiddleware, http_exception_handler
from pki_service.adapter.server_cli import close_client
from .routers.v1 import serv as serv_v1

setup_logging()
logger = logging.getLogger(__name__)

client_id = os.getenv("KC_CLI", "pki")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("pki service startup!")
    # pool for crypto service
    yield
    await close_client()
    logger.info("pki service shutdown!")

app = FastAPI(
    title = "pki service",
    debug=True,
    swagger_ui_oauth2_redirect_url="/docs/oauth2-redirect",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": client_id,
        "scopes": "openid profile email",},
    lifespan=lifespan,
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],   
)

app.add_middleware(ReqIDExceptionMiddleware)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.include_router(serv_v1.router, prefix="/v1/serv", tags=["server"])

@app.get("/health", status_code=200)
async def health_check():
    return {"message": "pki service!"}