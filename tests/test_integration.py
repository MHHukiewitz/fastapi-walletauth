import base58
import pytest
from fastapi import FastAPI, Depends
from fastapi.routing import APIRouter
from nacl.signing import SigningKey
from starlette.testclient import TestClient

from fastapi_walletauth.common import SupportedChains
from fastapi_walletauth.middleware import server_side_credentials_manager, BearerWalletAuth, ServerSideWalletAuthDep, \
    jwt_credentials_manager, JWTWalletAuthDep
from fastapi_walletauth.router import (
    jwt_authorization_router,
    server_side_authorization_router,
)

server_side_app = FastAPI()
server_side_app.include_router(server_side_authorization_router)
authorized_server_side_router = APIRouter(
    dependencies=[Depends(BearerWalletAuth(server_side_credentials_manager))]
)


@authorized_server_side_router.get("/authorized")
def authorized(
    user: ServerSideWalletAuthDep
):
    return {
        "address": user.address,
        "chain": user.chain,
    }


server_side_app.include_router(authorized_server_side_router)

jwt_app = FastAPI()
jwt_app.include_router(jwt_authorization_router)
authorized_jwt_router = APIRouter(
    dependencies=[Depends(BearerWalletAuth(jwt_credentials_manager))]
)


@authorized_jwt_router.get("/authorized")
def authorized(
    user: JWTWalletAuthDep
):
    return {
        "address": user.address,
        "chain": user.chain,
    }


jwt_app.include_router(authorized_jwt_router)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [
        TestClient(server_side_app),
        TestClient(jwt_app),
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

    token = data["token"]

    response = client.get(
        "/authorized",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
