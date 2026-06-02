# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import asyncio

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.proxy.app import create_app


@pytest.mark.asyncio
async def test_health_endpoint():
    settings = AegisSettings(
        backend_api_key="test-backend-key", wal_path="/tmp/health_test.wal", waf_strict_mode=False
    )
    app = create_app(settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
        print(f"Health response: {response.status_code}")
        assert response.status_code == 200


if __name__ == "__main__":
    import asyncio

    asyncio.run(test_health_endpoint())
