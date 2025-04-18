import base58
import pytest
import time
from nacl.signing import SigningKey
from starlette.testclient import TestClient
from eth_account import Account
import secrets
from starlette.exceptions import HTTPException

from fastapi_walletauth.common import SupportedChains, NotAuthorizedError
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
async def test_solana_router_integration(client):
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

    print("Challenge message to be signed:", data["challenge"])

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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [
        TestClient(server_side_authorization_router),
        TestClient(jwt_authorization_router),
    ],
)
async def test_ethereum_router_integration(client):
    chain = SupportedChains.Ethereum.value
    # Create an Ethereum account instead of using SigningKey
    private_key = secrets.token_bytes(32)
    account = Account.from_key(private_key)
    address = account.address

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

    print("Challenge message to be signed:", data["challenge"])

    # Sign the message using eth_account
    message = data["challenge"]
    # Create the Ethereum specific message
    from eth_account.messages import encode_defunct
    message_hash = encode_defunct(text=message)
    signed_message = Account.sign_message(message_hash, private_key=private_key)
    signature = signed_message.signature.hex()
    if not signature.startswith('0x'):
        signature = '0x' + signature

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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [
        TestClient(server_side_authorization_router),
        TestClient(jwt_authorization_router),
    ],
)
async def test_token_refresh(client):
    # First get a token via the standard flow
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    # Get a challenge
    response = client.post(
        "/authorization/challenge",
        params={"address": address, "chain": chain},
    )
    challenge = response.json()["challenge"]
    signature = base58.b58encode(key.sign(challenge.encode()).signature).decode("utf-8")

    # Solve the challenge to get a token
    response = client.post(
        "/authorization/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
        },
    )
    
    data = response.json()
    original_token = data["token"]
    original_valid_til = data["valid_til"]
    
    # Add a small delay to ensure timestamps will be different
    time.sleep(1)
    
    # Now refresh the token
    response = client.post(
        "/authorization/refresh",
        params={"token": original_token},
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
    assert "token" in data
    assert "valid_til" in data
    
    print(f"Original token: {original_token[:10]}... expires at: {original_valid_til}")
    print(f"Refreshed token: {data['token'][:10]}... expires at: {data['valid_til']}")
    
    assert data["valid_til"] >= original_valid_til


@pytest.mark.asyncio
async def test_jwt_token_refresh():
    """Test that JWT tokens actually change when refreshed (since they encode the expiration time)."""
    client = TestClient(jwt_authorization_router)
    
    # First get a token via the standard flow
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    # Get a challenge
    response = client.post(
        "/authorization/challenge",
        params={"address": address, "chain": chain},
    )
    challenge = response.json()["challenge"]
    signature = base58.b58encode(key.sign(challenge.encode()).signature).decode("utf-8")

    # Solve the challenge to get a token
    response = client.post(
        "/authorization/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
        },
    )
    
    data = response.json()
    original_token = data["token"]
    original_valid_til = data["valid_til"]
    
    # Add a small delay to ensure timestamps will be different
    time.sleep(1)
    
    # Now refresh the token
    response = client.post(
        "/authorization/refresh",
        params={"token": original_token},
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # For JWT, the token should absolutely change since it encodes the expiration time
    assert data["token"] != original_token, "JWT token should change when refreshed"
    assert data["valid_til"] > original_valid_til, "JWT token expiration should be extended"


@pytest.mark.asyncio
async def test_logout():
    """Test logout functionality for server-side auth only (JWT tokens don't support logout)"""
    client = TestClient(server_side_authorization_router)
    
    # First get a token via the standard flow
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    # Get a challenge
    response = client.post(
        "/authorization/challenge",
        params={"address": address, "chain": chain},
    )
    challenge = response.json()["challenge"]
    signature = base58.b58encode(key.sign(challenge.encode()).signature).decode("utf-8")

    # Solve the challenge to get a token
    response = client.post(
        "/authorization/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
        },
    )
    
    token = response.json()["token"]
    
    # Logout should work for server-side auth
    response = client.post(
        "/authorization/logout",
        params={"token": token},
    )
    assert response.status_code == 200
    
    # Setup the test
    from fastapi_walletauth.manager import ServerSideCredentialsManager
    
    # After logout, trying to refresh the token should raise a NotAuthorizedError
    with pytest.raises(NotAuthorizedError, match="Not authorized"):
        ServerSideCredentialsManager.refresh_token(token)
