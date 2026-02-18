import json
import pytest
import httpx
import os

# Config-driven test runner
def load_test_scenarios():
    config_path = os.path.join(os.path.dirname(__file__), "test_scenarios.json")
    with open(config_path, "r") as f:
        return json.load(f)

scenarios = load_test_scenarios()

@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", scenarios, ids=lambda s: s["name"])
async def test_api_integration(scenario):
    base_url = "http://localhost:8001"  # Target crypto_service
    url = f"{base_url}{scenario['endpoint']}"
    method = scenario.get("method", "POST")
    payload = scenario.get("payload", {})
    expected = scenario.get("expected", {})
    expected_status = scenario.get("expected_status", 200)

    async with httpx.AsyncClient(timeout=10.0) as client:
        if method == "POST":
            resp = await client.post(url, json=payload, params={"hsm_name": "GP"})
        elif method == "GET":
            resp = await client.get(url, params={"hsm_name": "GP"})
        
        # Verify status code
        assert resp.status_code == expected_status, f"Failed: {scenario['name']} - Content: {resp.text}"
        
        # Verify response body if expected data is provided
        if expected and resp.status_code == 200:
            resp_data = resp.json()
            for key, value in expected.items():
                assert resp_data.get(key) == value, f"Mismatch in {key}: expected {value}, got {resp_data.get(key)}"
