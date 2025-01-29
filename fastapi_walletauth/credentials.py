import os
import time
from abc import abstractmethod
from typing import Optional, TypeVar

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

    challenge: str = Field(default=None, init=False)
    internal_token: Optional[str] = Field(default=None, init=False)

    def __init__(
        self, address: str, chain: SupportedChains, ttl: int = settings.CHALLENGE_TTL
    ):
        valid_til = int(time.time()) + ttl
        challenge = f'{{"chain":"{chain.value}","address":"{address}","app":"{settings.APP}","time":"{time.time()}"}}'
        super().__init__(address=address, chain=chain, valid_til=valid_til)
        self.challenge = challenge
        self.internal_token = None

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

        if self.chain == SupportedChains.Solana:
            verify_signature_sol(
                signature=signature, public_key=self.address, message=self.challenge
            )
        elif self.chain == SupportedChains.Ethereum:
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


class SimpleWalletCredentials(WalletCredentials):
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
            self = cls(address=payload["sub"], chain=SupportedChains(payload["chain"]))
            self.valid_til = payload["exp"]
            self.internal_token = token

            return self
        except jwt.exceptions.PyJWTError as e:
            if e is jwt.exceptions.ExpiredSignatureError:
                raise TimeoutError("Token expired") from e
            raise NotAuthorizedError("Not authorized") from e


GenericWalletCredentials = TypeVar("GenericWalletCredentials", bound=WalletCredentials)
