# FastAPI Wallet Authentication

fastapi-walletauth provides a simple way to authenticate users in FastAPI applications using a wallet.
It currently supports Ethereum and Solana wallets/signatures.

## Installation

```shell
pip install fastapi-walletauth
```

## Usage

Adding the authentication endpoints is as simple as importing the `fastapi_walletauth.magic` module **after** the
FastAPI application has been created:

```python
from fastapi import FastAPI

app = FastAPI()

import fastapi_walletauth.magic
```

or if you prefer, you can add the endpoints manually:

```python
from fastapi import FastAPI
from fastapi_walletauth.router import authorization

app = FastAPI()

app.include_router(authorization)
```

This will add the following endpoints to your application:

- `POST /authentication/challenge`: Returns a challenge for the user to sign
- `POST /authentication/solve`: Returns a Bearer token if the signature is valid
- `POST /authentication/logout`: Invalidates the current token
- `POST /authentication/refresh`: Returns a new token if the current token is valid

You can then use `WalletAuthDep` to protect your endpoints:

```python
from fastapi import FastAPI
from fastapi_walletauth import WalletAuth, WalletAuthDep

app = FastAPI()

import fastapi_walletauth.magic

@app.get("/protected")
def protected(wa: WalletAuth = WalletAuthDep()):
    return wa.address
```

## Signing the challenge

The challenge is a JSON object (similar to Aleph messages) containing the following fields:

```python
message = {
    "chain": "ETH",
    "address": "0x...",
    "type": "authorization_challenge",
    "item_hash": "0x...",
}
```

- `chain`: The chain ID (e.g. `ETH` for Ethereum mainnet)
- `address`: The address of the user
- `type`: The type of message to be signed (`authorization_challenge`)
- `item_hash`: A random hash

Currently, it requires to be preprocessed into a *Verification Buffer* like this:
```python
"{chain}\n{sender}\n{type}\n{item_hash}".format(**message).encode("utf-8")
```

before being signed with the user's private key. This signature is then sent to the `/authentication/solve` endpoint.