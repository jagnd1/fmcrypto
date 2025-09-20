import asyncio
from contextlib import asynccontextmanager
import logging
import os
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from common.logging_config import setup_logging
from common.middlewares.reqid_exception import http_exception_handler
from common.middlewares.reqid_exception import ReqIDExceptionMiddleware
from crypto_service.usecase.hsm import HSMService
from .routers.v1 import crypto as crypto_v1

setup_logging()
logger = logging.getLogger(__name__)

hsm_name = os.getenv("CRYPTO_HSM", "GP")
hsm_service = HSMService(hsm_name)
hsm_obj = hsm_service(hsm_name)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("crypto service startup!")
    bt = asyncio.create_task(hsm_obj.check_client(60))
    yield
    bt.cancel()
    try:
        await bt
        await hsm_obj.close_client()
    except Exception as e:
        logger.error(f"error in cancelling bt: {e}")
    logger.info("crypto service shutdown!")

app = FastAPI(
    title="crypto service",
    debug=False,
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
app.include_router(crypto_v1.router, prefix="/v1/crypto", tags=["crypto"])

@app.get("/health", status_code=200)
async def health_check():
    return {"message": "crypto service!"}