# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import asyncio
import tempfile

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.proxy.app import create_app


@pytest.mark.asyncio
async def test_health_endpoint():
    with tempfile.TemporaryDirectory() as tmpdir:
        import os

        wal_path = os.path.join(tmpdir, "health_test.wal")
        settings = AegisSettings(
            backend_api_key="test-backend-key", wal_path=wal_path, waf_strict_mode=False
        )
        app = create_app(settings)

        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/health")
                print(f"Health response: {response.status_code}")
                assert response.status_code == 200
        finally:
            # Close the ledger handle so the temp directory can be cleaned up on Windows.
            try:
                app.state.aegis.ledger.close()
            except Exception:
                pass


if __name__ == "__main__":
    import asyncio

    asyncio.run(test_health_endpoint())
