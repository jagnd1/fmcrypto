import os
from functools import lru_cache


def _reset_settings_cache():
    """Clear the lru_cache to force reload with new env vars."""
    get_settings.cache_clear()


class Settings:
    environment: str = os.getenv("ENVIRONMENT", "development")

    # Zitadel
    # shared secret for service-to-service internal endpoints (verify_api_key)
    internal_api_secret: str = os.getenv("INTERNAL_API_SECRET", "dev-internal-secret")
    zitadel_domain: str = os.getenv("ZITADEL_DOMAIN", "http://localhost:8080")
    zitadel_project_id: str = os.getenv("ZITADEL_PROJECT_ID", "")
    zitadel_platform_org_id: str = os.getenv("ZITADEL_PLATFORM_ORG_ID", "")
    zitadel_internal_url: str = os.getenv("ZITADEL_INTERNAL_URL", "")
    zitadel_machine_user_id: str = os.getenv("ZITADEL_MACHINE_USER_ID", "")

    # DMS service
    dms_service_url: str = os.getenv("DMS_SERVICE_URL", "http://dms_service:8003")
    zitadel_external_domain: str = os.getenv("ZITADEL_EXTERNAL_DOMAIN", "http://localhost:8080")


@lru_cache
def get_settings() -> Settings:
    return Settings()