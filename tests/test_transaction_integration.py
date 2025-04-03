import base58
import base64
import pytest
from nacl.signing import SigningKey
from starlette.testclient import TestClient
import time
from eth_account import Account
import secrets

from fastapi_walletauth.common import SupportedChains, NotAuthorizedError
from fastapi_walletauth.router import (
    jwt_transaction_authorization_router,
    server_transaction_authorization_router,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [
        TestClient(server_transaction_authorization_router),
        TestClient(jwt_transaction_authorization_router),
    ],
)
async def test_transaction_router_integration(client):
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    response = client.post(
        "/transaction-auth/challenge",
        params={"address": address, "chain": chain},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
    assert "transaction" in data
    assert "valid_til" in data

    print("Transaction to be signed:", data["transaction"])  # Print the transaction

    # Decode the transaction
    transaction = data["transaction"]
    transaction_bytes = base64.b64decode(transaction)
    
    # For the simplified test case, directly sign the bytes of the transaction with nacl
    signature = base58.b58encode(key.sign(transaction_bytes).signature).decode("utf-8")

    response = client.post(
        "/transaction-auth/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
            "transaction": transaction,
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
        TestClient(server_transaction_authorization_router),
        TestClient(jwt_transaction_authorization_router),
    ],
)
async def test_ethereum_transaction_router_integration(client):
    chain = SupportedChains.Ethereum.value
    # Create an Ethereum account instead of using SigningKey
    private_key = secrets.token_bytes(32)
    account = Account.from_key(private_key)
    address = account.address

    response = client.post(
        "/transaction-auth/challenge",
        params={"address": address, "chain": chain},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
    assert "transaction" in data
    assert "valid_til" in data

    print("Ethereum transaction to be signed:", data["transaction"])

    # For Ethereum, transaction is hex-encoded
    transaction = data["transaction"]
    assert transaction.startswith("0x")
    transaction_bytes = bytes.fromhex(transaction[2:])
    
    # Sign the transaction using eth_account
    from eth_account.messages import encode_defunct
    message_hash = encode_defunct(text=transaction_bytes.decode())
    signed_tx = Account.sign_message(message_hash, private_key=private_key)
    signature = signed_tx.signature.hex()
    if not signature.startswith('0x'):
        signature = '0x' + signature

    response = client.post(
        "/transaction-auth/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
            "transaction": transaction,
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
        TestClient(server_transaction_authorization_router),
        TestClient(jwt_transaction_authorization_router),
    ],
)
async def test_transaction_token_refresh(client):
    # First get a token via the standard flow
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    # Get a challenge
    response = client.post(
        "/transaction-auth/challenge",
        params={"address": address, "chain": chain},
    )
    transaction = response.json()["transaction"]
    transaction_bytes = base64.b64decode(transaction)
    
    # For the simplified test case, directly sign the bytes of the transaction with nacl
    signature = base58.b58encode(key.sign(transaction_bytes).signature).decode("utf-8")

    # Solve the challenge to get a token
    response = client.post(
        "/transaction-auth/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
            "transaction": transaction,
        },
    )
    
    data = response.json()
    original_token = data["token"]
    original_valid_til = data["valid_til"]
    
    # Add a small delay to ensure timestamps will be different
    # This simulates real-world usage where refresh would happen later
    time.sleep(1)
    
    # Now refresh the token
    response = client.post(
        "/transaction-auth/refresh",
        params={"token": original_token},
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == address
    assert data["chain"] == chain
    assert "token" in data
    assert "valid_til" in data
    
    # Print debugging information to understand what's happening
    print(f"Original token: {original_token[:10]}... expires at: {original_valid_til}")
    print(f"Refreshed token: {data['token'][:10]}... expires at: {data['valid_til']}")
    
    # Our assertions about token and expiration time
    # For JWT tokens, the token should change (as it encodes the expiration time)
    # For server-side tokens, the token may or may not change, but validity must increase
    assert data["valid_til"] >= original_valid_til  # Valid time should be at least the same or extended


@pytest.mark.asyncio
async def test_jwt_transaction_token_refresh():
    """Test that JWT tokens actually change when refreshed (since they encode the expiration time)."""
    client = TestClient(jwt_transaction_authorization_router)
    
    # First get a token via the standard flow
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    # Get a challenge
    response = client.post(
        "/transaction-auth/challenge",
        params={"address": address, "chain": chain},
    )
    transaction = response.json()["transaction"]
    transaction_bytes = base64.b64decode(transaction)
    
    # For the simplified test case, directly sign the bytes of the transaction with nacl
    signature = base58.b58encode(key.sign(transaction_bytes).signature).decode("utf-8")

    # Solve the challenge to get a token
    response = client.post(
        "/transaction-auth/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
            "transaction": transaction,
        },
    )
    
    data = response.json()
    original_token = data["token"]
    original_valid_til = data["valid_til"]
    
    # Add a small delay to ensure timestamps will be different
    time.sleep(1)
    
    # Now refresh the token
    response = client.post(
        "/transaction-auth/refresh",
        params={"token": original_token},
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # For JWT, the token should absolutely change since it encodes the expiration time
    assert data["token"] != original_token, "JWT token should change when refreshed"
    assert data["valid_til"] > original_valid_til, "JWT token expiration should be extended"


@pytest.mark.asyncio
async def test_logout():
    """Test logout functionality for server-side transaction auth only (JWT tokens don't support logout)"""
    client = TestClient(server_transaction_authorization_router)
    
    # First get a token via the standard flow
    chain = SupportedChains.Solana.value
    key = SigningKey.generate()
    address = base58.b58encode(bytes(key.verify_key)).decode("utf-8")

    # Get a challenge
    response = client.post(
        "/transaction-auth/challenge",
        params={"address": address, "chain": chain},
    )
    transaction = response.json()["transaction"]
    transaction_bytes = base64.b64decode(transaction)
    
    # For the simplified test case, directly sign the bytes of the transaction with nacl
    signature = base58.b58encode(key.sign(transaction_bytes).signature).decode("utf-8")

    # Solve the challenge to get a token
    response = client.post(
        "/transaction-auth/solve",
        params={
            "address": address,
            "chain": chain,
            "signature": signature,
            "transaction": transaction,
        },
    )
    
    token = response.json()["token"]
    
    # Logout should work for server-side auth
    response = client.post(
        "/transaction-auth/logout",
        params={"token": token},
    )
    assert response.status_code == 200
    
    # Setup the test
    from fastapi_walletauth.manager import ServerSideTransactionCredentialsManager
    
    # After logout, trying to refresh the token should raise a NotAuthorizedError
    with pytest.raises(NotAuthorizedError, match="Not authorized"):
        ServerSideTransactionCredentialsManager.refresh_token(token) 