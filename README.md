# FastAPI Wallet Authentication

fastapi-walletauth provides a simple way to authenticate users in FastAPI applications using a wallet.
It currently supports Ethereum and Solana wallets/signatures.

## Installation

```shell
pip install fastapi-walletauth
```

## Usage

Adding the authentication endpoints is as simple as importing the `authorization_routes` from `fastapi_walletauth`:

```python
from fastapi import FastAPI
from fastapi_walletauth import jwt_authorization_router

app = FastAPI()

app.include_router(jwt_authorization_router)
```

This will add the following endpoints to your application:

- `POST /authentication/challenge`: Returns a challenge for the user to sign
- `POST /authentication/solve`: Returns a Bearer token if the signature is valid
- `POST /authentication/logout`: Invalidates the current token
- `POST /authentication/refresh`: Returns a new token if the current token is valid

You can then use `WalletAuthDep` to protect your endpoints:

```python
from fastapi import FastAPI
from fastapi_walletauth import JWTWalletAuthDep, jwt_authorization_router

app = FastAPI()
app.include_router(jwt_authorization_router)

@app.get("/protected")
def protected(wa: JWTWalletAuthDep):
    return wa.address
```

## Signing the challenge

The challenge message is now formatted in a human-readable way and includes the following fields:

```
Hello, please sign this message!
Chain: ETH
Address: 0x...
App: myapp
Time: 2025-01-29 15:22:39
```

**PLEASE NOTE**: The `app` field needs to be set to the name of your application. This is used to prevent replay attacks.
```shell
export FASTAPI_WALLETAUTH_APP=myapp
```

The signature format depends on the wallet type and is specified in the `chain` field. This signature is then sent to the `/authentication/solve` endpoint to obtain a Bearer token.

## Transaction-Based Authentication (New in v2.2.0)

Starting from version 2.2.0, `fastapi-walletauth` supports transaction-based authentication as an alternative to message signing. This is especially useful for hardware wallets (like Ledger) that may not support message signing in browser wallets.

### Using Transaction-Based Authentication

To enable transaction-based authentication, import the transaction authorization router:

```python
from fastapi import FastAPI
from fastapi_walletauth import jwt_transaction_authorization_router

app = FastAPI()

app.include_router(jwt_transaction_authorization_router)
```

This adds the following endpoints to your application:

- `POST /transaction-auth/challenge`: Returns a transaction to sign instead of a message
- `POST /transaction-auth/solve`: Returns a Bearer token if the transaction signature is valid
- `POST /transaction-auth/refresh`: Returns a new token if the current token is valid

### Transaction Challenge Format

The transaction challenges are simple memo transactions:

- For Solana: A basic transaction with a memo instruction containing the challenge message
- For Ethereum: A zero-value transaction to the zero address with the challenge message in the data field

### Signing Transactions

The flow for transaction-based authentication is:

1. Request a challenge transaction at `/transaction-auth/challenge`
2. Sign the transaction with your wallet (without sending it to the blockchain)
3. Submit the transaction signature and the transaction to `/transaction-auth/solve`
4. Use the returned token for subsequent authenticated requests

This approach is compatible with hardware wallets that support transaction signing but not message signing.

## Custom Greeting Configuration

Starting from version 2.1.0, `fastapi-walletauth` allows you to configure a custom greeting message that will be included in the challenge message. This greeting can be set in the server configuration and will be used for all challenge messages.

### Setting the Greeting

The greeting message can be configured in the `Settings` class within your application. By default, the greeting is set to "Hello, please sign this message!". You can change this by setting the `GREETING` environment variable or by modifying the `Settings` class directly.

Example:

```python
from fastapi_walletauth.common import settings

# Set a custom greeting
settings.GREETING = "Welcome! Please sign this message to continue."
```

## Liability

This software is provided "as is" and "with all faults." I make no representations or warranties of any kind concerning
the safety, suitability, inaccuracies, typographical errors, or other harmful components of this
software. There are inherent dangers in the use of any software, especially cryptographic implementations. You are solely
responsible for determining whether this software is compatible with your machine and other software installed on your
computer. You are also solely responsible for the choice of a wallet and the security of your private keys. You
acknowledge and agree to waive any liability claim against me from any loss or damage of any kind arising out of or in
connection with your use of this software.