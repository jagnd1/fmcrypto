from starlette.requests import Request
import pytest

from common.middlewares.auth import get_current_user, settings
from common.middlewares.reqid_exception import UnAuthException


def _request(headers=None):
    raw_headers = [
        (key.lower().encode(), value.encode())
        for key, value in (headers or {}).items()
    ]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw_headers})


def test_internal_service_secret_authenticates_without_bearer_token():
    dependency = get_current_user(["route:entity:read"])

    user = dependency(
        _request({"X-Internal-Secret": settings.internal_api_secret}), token=None
    )

    assert user.user_id == "service:internal"
    assert user.roles == ["route:entity:read"]
    assert user.raw_token is None


def test_device_api_key_is_not_needed_for_internal_service_auth():
    dependency = get_current_user(["route:entity:read"])

    user = dependency(
        _request({
            "X-Internal-Secret": settings.internal_api_secret,
            "X-API-Key": "opaque-device-key",
        }),
        token=None,
    )

    assert user.user_id == "service:internal"
    assert user.roles == ["route:entity:read"]


def test_protected_route_still_rejects_missing_credentials():
    dependency = get_current_user(["route:entity:read"])

    with pytest.raises(UnAuthException):
        dependency(_request(), token=None)
