from dataclasses import dataclass, asdict
from os import putenv

import pytest
from .core import AuthTokenManager, SupportedChains
from nacl.signing import SigningKey
from fastapi import HTTPException
from starlette.testclient import TestClient
from .router import authorization, create_challenge, solve_challenge
from .verification import BadSignatureError
import base58

putenv("TEST_CHANNEL", "true")


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


@pytest.fixture
def client():
    return TestClient(authorization)


def test_create_challenge(client):
    chain = SupportedChains.Ethereum.value
    address = '0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'

    AuthTokenManager.get_challenge(address, chain)
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


@pytest.mark.asyncio
async def test_solve_challenge(client):
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    challenge = await create_challenge(address, chain)

    signature = base58.b58encode(key.sign(challenge.challenge.encode()).signature).decode("utf-8")

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


def test_solve_challenge_with_forged_signature(client):
    chain = SupportedChains.Ethereum.value
    address = '0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'

    wrong_signature = "0x" + "0" * 130
    with pytest.raises(BadSignatureError):
        AuthTokenManager.solve_challenge(address, chain, wrong_signature)
        response = client.post("/solve", params={"address": address, "chain": chain, "signature": wrong_signature})
        assert response.status_code == 403
        assert HTTPException(403, "Challenge failed")


@pytest.mark.asyncio
async def test_refresh_token(client):
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    challenge = await create_challenge(address, chain)

    signature = base58.b58encode(key.sign(challenge.challenge.encode()).signature).decode("utf-8")

    solve_response = await solve_challenge(address, chain, signature)

    response = client.post(
        "/authorization/refresh",
        params={"token": solve_response.token},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
    assert data["token"] == solve_response.token
    assert "valid_til" in data

    with pytest.raises(HTTPException):
        client.post(
            "/authorization/refresh",
            params={"token": "0x" + "0" * 130},
        )

    assert HTTPException(403, "Not authorized")


@pytest.mark.asyncio
async def test_logout(client):
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    challenge = await create_challenge(address, chain)

    signature = base58.b58encode(key.sign(challenge.challenge.encode()).signature).decode("utf-8")

    solve_response = await solve_challenge(address, chain, signature)

    response = client.post(
        "/authorization/logout",
        params={"token": solve_response.token},
    )

    assert response.status_code == 200


def test_challenge_timeout(client):
    expired_token = ""

    with pytest.raises(HTTPException):
        client.post(
            "/authorization/refresh",
            params={"token": expired_token},
        )

    assert HTTPException(403, "Token expired")
