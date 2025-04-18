import os
import time
from abc import abstractmethod
from typing import Optional, TypeVar, Union

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from fastapi_walletauth.common import NotAuthorizedError, SupportedChains, settings
from fastapi_walletauth.verification import verify_signature_eth, verify_signature_sol


class WalletCredentialsInfo(BaseModel):
    address: str
    chain: SupportedChains
    valid_til: int


class WalletCredentials(WalletCredentialsInfo):
    """
    A credentials object containing a challenge and a token. The challenge is a string that needs to be signed by the
    user's wallet. The token is created when successfully solving the challenge and used to authenticate the user with
    the server.
    """

    challenge: str = Field(default="", init=False)
    internal_token: Optional[str] = Field(default=None, init=False)
    greeting: Optional[str] = None  # New optional greeting field

    def __init__(
        self, address: str, chain: SupportedChains, ttl: int = settings.CHALLENGE_TTL, greeting: Optional[str] = None, 
        valid_til: Optional[int] = None
    ):
        if valid_til is None:
            valid_til = int(time.time()) + ttl
        # Use the server-configured greeting
        greeting = settings.GREETING

        # Improved message formatting
        message_parts = [
            greeting,
            f"Chain: {chain.value}",
            f"Address: {address}",
            f"App: {settings.APP}",
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}"
        ]
        challenge = "\n".join(part for part in message_parts if part)
        super().__init__(address=address, chain=chain, valid_til=valid_til)
        self.challenge = challenge
        self.internal_token = None
        object.__setattr__(self, 'greeting', greeting)  # Use object.__setattr__ to set greeting

    @property
    def token(self) -> Optional[str]:
        if self.expired:
            raise TimeoutError("Token Expired")
        if self.internal_token is False:
            return None
        return self.internal_token

    @property
    def expired(self):
        return int(time.time()) > self.valid_til

    def solve_challenge(self, signature: str):
        if self.expired:
            raise TimeoutError("Challenge Expired")

        if self.chain.value == SupportedChains.Solana.value:
            verify_signature_sol(
                signature=signature, public_key=self.address, message=self.challenge
            )
        elif self.chain.value == SupportedChains.Ethereum.value:
            verify_signature_eth(
                signature=signature, public_key=self.address, message=self.challenge
            )
        else:
            raise NotImplementedError(
                f"{self.chain} has no verification function implemented"
            )

        self.refresh_token()

    @abstractmethod
    def refresh_token(self, ttl: int = settings.TOKEN_TTL):
        raise NotImplementedError


class TransactionWalletCredentials(WalletCredentials):
    """
    A credentials object that uses transactions for challenges instead of plain messages.
    This allows for hardware wallet support (like Ledger) that may not support message signing.
    """
    transaction: str = Field(default="", init=False)
    
    def __init__(
        self, address: str, chain: SupportedChains, ttl: int = settings.CHALLENGE_TTL, greeting: Optional[str] = None,
        valid_til: Optional[int] = None
    ):
        valid_til = valid_til or int(time.time()) + ttl
        super().__init__(address=address, chain=chain, ttl=ttl, greeting=greeting, valid_til=valid_til)
        # The transaction will be generated specifically for each chain in the manager
        self.transaction = ""

    def solve_transaction_challenge(self, signature: str, transaction: str):
        """
        Solves a challenge using a signed transaction.
        
        Args:
            signature: The transaction signature
            transaction: The transaction that was signed (should match the challenge transaction)
        """
        if self.expired:
            raise TimeoutError("Challenge Expired")
            
        if self.transaction != transaction:
            raise ValueError("Transaction does not match the challenge")
            
        # Verification of the signature happens in chain-specific implementations
        
        self.refresh_token()


class SimpleWalletCredentials(WalletCredentials):
    def refresh_token(self, ttl: int = settings.TOKEN_TTL):
        self.internal_token = os.urandom(64).hex()
        self.valid_til = int(time.time()) + ttl


class SimpleTransactionWalletCredentials(TransactionWalletCredentials):
    def refresh_token(self, ttl: int = settings.TOKEN_TTL):
        self.internal_token = os.urandom(64).hex()
        self.valid_til = int(time.time()) + ttl


class JWTWalletCredentials(WalletCredentials):
    def refresh_token(self, ttl: int = settings.TOKEN_TTL):
        self.valid_til = int(time.time()) + ttl
        payload = {
            "iss": settings.APP,
            "sub": self.address,
            "exp": self.valid_til,
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "chain": self.chain.value,
        }
        headers = {
            "alg": "EdDSA",
            "crv": "Ed25519",
            "typ": "JWT",
        }
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(settings.PRIVATE_KEY))
        self.internal_token = jwt.encode(
            payload, private_key, algorithm="EdDSA", headers=headers
        )

    @classmethod
    def from_token(cls, token: str):
        try:
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(settings.PUBLIC_KEY))
            payload = jwt.decode(token, public_key, algorithms=["EdDSA"])
            # Extract data from payload
            address = payload["sub"]
            chain = SupportedChains(payload["chain"])
            valid_til = payload["exp"]
            
            # Create instance with all required fields directly
            self = cls(address=address, chain=chain, valid_til=valid_til)
            # Set token
            self.internal_token = token

            return self
        except jwt.exceptions.PyJWTError as e:
            if isinstance(e, jwt.exceptions.ExpiredSignatureError):
                raise TimeoutError("Token expired") from e
            raise NotAuthorizedError("Not authorized") from e


class JWTTransactionWalletCredentials(TransactionWalletCredentials):
    def refresh_token(self, ttl: int = settings.TOKEN_TTL):
        self.valid_til = int(time.time()) + ttl
        payload = {
            "iss": settings.APP,
            "sub": self.address,
            "exp": self.valid_til,
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "chain": self.chain.value,
        }
        headers = {
            "alg": "EdDSA",
            "crv": "Ed25519",
            "typ": "JWT",
        }
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(settings.PRIVATE_KEY))
        self.internal_token = jwt.encode(
            payload, private_key, algorithm="EdDSA", headers=headers
        )

    @classmethod
    def from_token(cls, token: str):
        try:
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(settings.PUBLIC_KEY))
            payload = jwt.decode(token, public_key, algorithms=["EdDSA"])
            # Extract data from payload
            address = payload["sub"]
            chain = SupportedChains(payload["chain"])
            valid_til = payload["exp"]
            
            # Create instance with all required fields
            self = cls(address=address, chain=chain, valid_til=valid_til)
            # Set token
            self.internal_token = token

            return self
        except jwt.exceptions.PyJWTError as e:
            if isinstance(e, jwt.exceptions.ExpiredSignatureError):
                raise TimeoutError("Token expired") from e
            raise NotAuthorizedError("Not authorized") from e


GenericWalletCredentials = TypeVar("GenericWalletCredentials", bound=WalletCredentials)
