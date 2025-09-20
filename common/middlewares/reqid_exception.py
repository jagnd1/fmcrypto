import logging
import uuid
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
import traceback

logger = logging.getLogger(__name__)

class BusinessLogicException(Exception):
    """ custom exception for business logic """
    def __init__(self, detail: str):
        self.detail = detail

class AdapterException(Exception):
    """ custom exception for adpater level """
    def __init__(self, detail: str):
        self.detail = detail

class TimeoutException(Exception):
    """ custom exception for adapter timeout """
    def __init__(self, detail: str):
        self.detail = detail


class ReqIDExceptionMiddleware:
    """ middleware for req id log and exception handling """
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        # filter out non http reqs
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # gen unique req id
        req_id = str(uuid.uuid4())
        req = Request(scope)
        scope['state']['request_id'] = req_id
        # wrapper fn to modify response
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"x-request-id"] = req_id.encode()
                message["headers"] = list(headers.items())
            await send(message)
        # send the req
        try: 
            logger.info(f"Req before req id: {req_id} = {req.method} - {req.url}")
            await self.app(scope, receive, send_wrapper)
            logger.info(f"req id: {req_id} = {req.method} - {req.url}")
            logger.info(f"Res after id: {req_id} = {req.method} - {req.url}")
        # exception processing
        except Exception as e:
            # handle different exceptions
            if isinstance(e, BusinessLogicException):
                response = JSONResponse(
                    status_code=400, content={"status": "error", "detail": str(e.detail)})
            elif isinstance(e, AdapterException):
                logger.error(f"[{req_id}] adapter error: {str(e)}")
                response = JSONResponse(
                    status_code=502, content={"status": "error", "detail": str(e.detail)})
            elif isinstance(e, TimeoutException):
                logger.error(f"[{req_id}] timeout: {str(e)}")
                response = JSONResponse(
                    status_code=504, content={"status": "error", "detail": str(e.detail)})
            else:
                logger.exception(f"[{req_id}] unhandled err")
                traceback.print_exc()
                response = JSONResponse(
                    status_code=500, content={"status": "error", "detail": "interal server err!"})
            await response(scope, receive, send)

async def http_exception_handler(_: Request, exc: StarletteHTTPException):
    logger.warning(f"http exception: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code, content={"status": "error", "detail": exc.detail}) 