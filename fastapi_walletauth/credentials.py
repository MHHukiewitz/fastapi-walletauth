import os
import time
from abc import abstractmethod
from typing import Optional, TypeVar

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, Field

from fastapi_walletauth.common import SupportedChains, NotAuthorizedError, settings
from fastapi_walletauth.verification import verify_signature_sol, verify_signature_eth


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
    challenge: str
    _token: Optional[str] = Field(..., alias="token")

    class Config:
        allow_population_by_field_name = True
        extra = "allow"

    def __init__(self, address: str, chain: SupportedChains, ttl: int = settings.CHALLENGE_TTL):
        valid_til = int(time.time()) + ttl
        challenge = f'{{"chain":"{chain}","address":"{address}","app":"{settings.APP}","time":"{time.time()}"}}'
        super().__init__(address=address, chain=chain, valid_til=valid_til, challenge=challenge)  # type: ignore

    @property
    def token(self) -> Optional[str]:
        if self.expired:
            raise TimeoutError("Token Expired")
        if self._token is False:
            return None
        return self._token

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
        self._token = os.urandom(64).hex()
        self.valid_til = int(time.time()) + ttl


class JWTWalletCredentials(WalletCredentials):
    def refresh_token(self, ttl: int = settings.TOKEN_TTL):
        self.valid_til = int(time.time()) + ttl
        payload = {
            'iss': settings.APP,
            'sub': self.address,
            'exp': self.valid_til,
            'iat': int(time.time()),
            'nbf': int(time.time()),
            'chain': self.chain.value,
        }
        headers = {
            'alg': 'EdDSA',
            'crv': 'Ed25519',
            'typ': 'JWT',
        }
        private_key = Ed25519PrivateKey.from_private_bytes(settings.PRIVATE_KEY)
        self._token = jwt.encode(payload, private_key, algorithm='EdDSA', headers=headers)

    @classmethod
    def from_token(cls, token: str):
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(settings.PRIVATE_KEY)
            payload = jwt.decode(token, private_key, algorithms=['EdDSA'])
            self = cls(payload['sub'], payload['chain'])
            self.valid_til = payload['exp']
            self._token = token

            return self
        except jwt.exceptions.PyJWTError as e:
            if e is jwt.exceptions.ExpiredSignatureError:
                raise TimeoutError("Token expired") from e
            raise NotAuthorizedError("Not authorized") from e


GenericWalletCredentials = TypeVar('GenericWalletCredentials', bound=WalletCredentials)
