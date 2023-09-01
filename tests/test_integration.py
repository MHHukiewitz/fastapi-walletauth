from dataclasses import dataclass
from os import putenv

import pytest
from nacl.signing import SigningKey
from fastapi import HTTPException
from starlette.testclient import TestClient

from fastapi_walletauth.common import SupportedChains
from fastapi_walletauth.manager import ServerSideCredentialsManager
from fastapi_walletauth.router import server_side_authorization_router, jwt_authorization_router
from fastapi_walletauth.verification import BadSignatureError
import base58


@pytest.mark.asyncio
@pytest.mark.parametrize("client", [
    TestClient(server_side_authorization_router),
    TestClient(jwt_authorization_router)
])
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

    signature = base58.b58encode(key.sign(data["challenge"].encode()).signature).decode("utf-8")

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
