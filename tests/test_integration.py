import base58
import pytest
from nacl.signing import SigningKey
from starlette.testclient import TestClient

from fastapi_walletauth.common import SupportedChains
from fastapi_walletauth.router import (
    jwt_authorization_router,
    server_side_authorization_router,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [
        TestClient(server_side_authorization_router),
        TestClient(jwt_authorization_router),
    ],
)
async def test_router_integration(client):
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    response = client.post(
        "/authorization/challenge",
        params={"address": address, "chain": chain},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
    assert "challenge" in data
    assert "valid_til" in data

    signature = base58.b58encode(key.sign(data["challenge"].encode()).signature).decode(
        "utf-8"
    )

    response = client.post(
        "/authorization/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
    assert "token" in data
    assert "valid_til" in data


# TODO: test refresh, logout
