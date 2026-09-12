import hashlib
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional

import jwt
from jwt import PyJWK
from fastapi import Depends, Request
from fastapi.security import OAuth2AuthorizationCodeBearer

import httpx

from common.config import get_settings
from common.middlewares.reqid_exception import ForbiddenException, UnAuthException


settings = get_settings()
logger = logging.getLogger(__name__)

zitadel_domain = settings.zitadel_domain.rstrip("/")
zitadel_platform_org_id = settings.zitadel_platform_org_id


def _extract_org_id_from_roles(payload: dict) -> str:
    """Extract org_id from JWT roles claim."""
    roles_claim = payload.get("urn:zitadel:iam:org:project:roles", {})

    if not roles_claim:
        for key in payload:
            if "org:project:" in key and ":roles" in key:
                roles_claim = payload[key]
                break

    if roles_claim:
        for role_name, org_map in roles_claim.items():
            if org_map and isinstance(org_map, dict):
                for org_id in org_map.keys():
                    return org_id

    return ""


swagger_domain = settings.zitadel_external_domain

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{swagger_domain}/oauth/v2/authorize",
    tokenUrl=f"{swagger_domain}/oauth/v2/token",
    refreshUrl=f"{swagger_domain}/oauth/v2/token",
    scopes={"openid": "OpenID Connect scope"},
)

oauth2_scheme_optional = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{swagger_domain}/oauth/v2/authorize",
    tokenUrl=f"{swagger_domain}/oauth/v2/token",
    refreshUrl=f"{swagger_domain}/oauth/v2/token",
    scopes={"openid": "OpenID Connect scope"},
    auto_error=False,
)


@dataclass
class UserContext:
    user_id: str
    org_id: str
    roles: List[str]
    raw_token: str
    is_platform_admin: bool = False


service_account_user_id = settings.zitadel_machine_user_id
is_development = settings.environment != "production"


@lru_cache
def _get_jwks() -> dict:
    """Fetch JWKS from Zitadel."""
    internal_url = settings.zitadel_internal_url
    if internal_url:
        jwks_url = f"{internal_url.rstrip('/')}/oauth/v2/keys"
        host_header = "localhost:8080"
    else:
        jwks_url = f"{zitadel_domain}/oauth/v2/keys"
        host_header = None

    headers = {"Host": host_header} if host_header else {}
    with httpx.Client() as client:
        resp = client.get(jwks_url, headers=headers, timeout=10.0)
        resp.raise_for_status()
        return resp.json()


def _get_signing_key_from_jwt(token: str) -> jwt.PyJWK:
    """Get the signing key for a JWT."""
    jwks = _get_jwks()
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("No 'kid' in token header")

    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return jwt.PyJWK.from_dict(key)

    raise jwt.InvalidTokenError(f"Unable to find matching key for kid '{kid}'")


def decode_token(token: str):
    """Decode and verify a Zitadel-issued JWT."""
    if settings.environment == "test":
        return jwt.decode(token, options={"verify_signature": False, "verify_iss": False, "verify_aud": False})

    try:
        signing_key = _get_signing_key_from_jwt(token)

        decode_kwargs = {
            "algorithms": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"],
            "issuer": zitadel_domain,
        }
        if settings.zitadel_project_id:
            decode_kwargs["audience"] = settings.zitadel_project_id

        payload = jwt.decode(token, signing_key.key, **decode_kwargs)
        return payload
    except jwt.ExpiredSignatureError as e:
        raise UnAuthException(f"token has expired: {e}")
    except jwt.InvalidTokenError as e:
        raise ForbiddenException(f"token verification failed: {e}")


def require_permission(*required_scopes):
    """Dependency that requires specific permissions."""
    def get_user_with_permission(token: str = Depends(oauth2_scheme)) -> UserContext:
        payload = decode_token(token)

        roles_claim = payload.get('urn:zitadel:iam:org:project:roles', {})
        roles_list = list(roles_claim.keys())

        if required_scopes and not any(s in roles_list for s in required_scopes):
            if is_development and service_account_user_id and payload.get("sub") == service_account_user_id:
                logger.warning(f"SA bypass: granting {required_scopes} to service account")
                roles_list = list(required_scopes)
            else:
                raise ForbiddenException(f"missing required permission: {required_scopes}")

        org_id = payload.get("urn:zitadel:iam:org:id", "")
        if not org_id:
            org_id = _extract_org_id_from_roles(payload)

        is_sa = is_development and bool(service_account_user_id) and payload.get("sub") == service_account_user_id
        org_match = bool(zitadel_platform_org_id) and org_id == zitadel_platform_org_id
        has_admin_role = "route:partner:create" in roles_list
        is_platform_admin = is_sa or (org_match and has_admin_role)

        return UserContext(
            user_id=payload.get("sub", ""),
            org_id=org_id,
            roles=roles_list,
            raw_token=token,
            is_platform_admin=is_platform_admin,
        )
    return get_user_with_permission


def _verify_api_key(api_key: str) -> Optional[dict]:
    """Call dms_service to verify an API key and return its data."""
    dms_url = settings.dms_service_url.rstrip("/")
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{dms_url}/v1/sys/internal/verify_api_key",
                json={"key_hash": key_hash},
                headers={"X-Internal-Secret": settings.internal_api_secret},
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"API key verify call failed: {e}")
    return None


async def verify_api_key_async(api_key: str) -> Optional[dict]:
    """Async variant of _verify_api_key for async handlers."""
    dms_url = settings.dms_service_url.rstrip("/")
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{dms_url}/v1/sys/internal/verify_api_key",
                json={"key_hash": key_hash},
                headers={"X-Internal-Secret": settings.internal_api_secret},
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"API key verify (async) call failed: {e}")
    return None


def get_current_user(required_scopes: Optional[List[str]] = None, optional: bool = False):
    """Dependency that returns UserContext after validating required scopes.

    Supports dual-mode auth: Bearer JWT (primary) or X-API-Key (fallback when optional=True).

    When ``optional=True`` and no credentials are presented the request is allowed through
    (returns None) so the service stays usable standalone; credentials are always validated
    whenever they are present.
    """
    scheme = oauth2_scheme_optional
    def dependency(request: Request, token: str = Depends(scheme)) -> Optional[UserContext]:
        internal_secret = request.headers.get("x-internal-secret")
        if not token and internal_secret and internal_secret == settings.internal_api_secret:
            return UserContext(
                user_id="service:internal", org_id="",
                roles=list(required_scopes) if required_scopes else [],
                raw_token=None, is_platform_admin=False,
            )

        api_key = request.headers.get("x-api-key") if not token else None

        if not token and api_key:
            key_data = _verify_api_key(api_key)
            if not key_data:
                raise UnAuthException("invalid API key")

            roles_list = key_data.get("scopes", "").split(",") if key_data.get("scopes") else []

            if required_scopes and not any(s in roles_list for s in required_scopes):
                raise ForbiddenException("insufficient permission")

            return UserContext(
                user_id=f"apikey:{key_data.get('parent_id', 'unknown')}",
                org_id=key_data.get("parent_id", ""),
                roles=roles_list,
                raw_token=api_key,
                is_platform_admin=False,
            )

        if not token:
            if optional:
                return None
            raise UnAuthException("authentication required")

        try:
            payload = decode_token(token)
        except (UnAuthException, ForbiddenException):
            internal_secret = request.headers.get("x-internal-secret")
            if internal_secret and internal_secret == settings.internal_api_secret:
                return UserContext(
                    user_id="service:internal", org_id="",
                    roles=list(required_scopes) if required_scopes else [],
                    raw_token=None, is_platform_admin=False,
                )
            raise

        roles_claim = payload.get('urn:zitadel:iam:org:project:roles', {})
        roles_list = list(roles_claim.keys())

        if required_scopes and not any(s in roles_list for s in required_scopes):
            if is_development and service_account_user_id and payload.get("sub") == service_account_user_id:
                logger.warning(f"SA bypass: granting {required_scopes} to service account")
                roles_list = list(required_scopes)
            else:
                raise ForbiddenException("insufficient permission")

        org_id = payload.get("urn:zitadel:iam:org:id", "")
        if not org_id:
            org_id = _extract_org_id_from_roles(payload)

        is_sa = is_development and bool(service_account_user_id) and payload.get("sub") == service_account_user_id
        org_match = bool(zitadel_platform_org_id) and org_id == zitadel_platform_org_id
        has_admin_role = "route:partner:create" in roles_list
        is_platform_admin = is_sa or (org_match and has_admin_role)

        return UserContext(
            user_id=payload.get("sub", ""),
            org_id=org_id,
            roles=roles_list,
            raw_token=token,
            is_platform_admin=is_platform_admin,
        )
    return dependency