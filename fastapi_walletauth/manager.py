import time
from abc import abstractmethod
from typing import Dict, Generic, Type, Optional

from fastapi_walletauth.common import NotAuthorizedError, SupportedChains, settings
from fastapi_walletauth.credentials import (
    GenericWalletCredentials,
    JWTWalletCredentials,
    SimpleWalletCredentials,
)


class CredentialsManager(Generic[GenericWalletCredentials]):
    """
    A self-updating dictionary keeping track of all authentication tokens and signature challenges.
    """

    __challenges: Dict[str, GenericWalletCredentials] = {}
    """Keeps track of all solved and unsolved challenges. Keys have format `<address>-<chain>`."""

    credentials_type: Type[GenericWalletCredentials]

    @classmethod
    def get_token(cls, address: str, chain: SupportedChains) -> str:
        try:
            return cls.__challenges[address + "-" + str(chain)].token
        except (TimeoutError, AttributeError) as e:
            if e is TimeoutError:
                cls.remove_challenge(address, chain)
            if e is AttributeError:
                raise NotAuthorizedError("Not authorized") from e
            raise e

    @classmethod
    def get_challenge(
        cls, address: str, chain: SupportedChains, greeting: Optional[str] = None
    ) -> GenericWalletCredentials:
        auth = cls.__challenges.get(address + "-" + str(chain))
        if auth is None or int(time.time()) > auth.valid_til:
            auth = cls.credentials_type(address=address, chain=chain, greeting=greeting)
            cls.__challenges[address + "-" + str(chain)] = auth
        return auth

    @classmethod
    def remove_challenge(cls, address: str, chain: SupportedChains) -> None:
        cls.__challenges.pop(address + "-" + str(chain))

    @classmethod
    def solve_challenge(
        cls, address: str, chain: SupportedChains, signature: str
    ) -> GenericWalletCredentials:
        auth = cls.get_challenge(address, chain)
        auth.solve_challenge(signature)
        return auth

    @classmethod
    @abstractmethod
    def get_auth_by_token(cls, token: str) -> GenericWalletCredentials:
        raise NotImplementedError

    @classmethod
    def refresh_token(
        cls, token: str, ttl: int = settings.TOKEN_TTL
    ) -> GenericWalletCredentials:
        raise NotImplementedError


class ServerSideCredentialsManager(CredentialsManager[SimpleWalletCredentials]):
    """
    This class is used to manage authentication tokens and signature challenges on the server side.
    A self-updating dictionary keeping track of all authentication tokens and signature challenges.
    """

    __auths: Dict[str, SimpleWalletCredentials] = {}
    """Maps all authentication tokens to their respective `WalletAuth` objects."""

    credentials_type = SimpleWalletCredentials

    @classmethod
    def get_auth_by_token(cls, token: str) -> SimpleWalletCredentials:
        auth = cls.__auths.get(token)
        if not auth:
            raise NotAuthorizedError("Not authorized")
        if auth.expired:
            cls.remove_challenge(address=auth.address, chain=auth.chain)
            raise TimeoutError("Token expired")
        return auth

    @classmethod
    def solve_challenge(
        cls, address: str, chain: SupportedChains, signature: str
    ) -> SimpleWalletCredentials:
        auth = super().solve_challenge(address, chain, signature)
        assert auth.token
        cls.__auths[auth.token] = auth
        return auth

    @classmethod
    def unregister_auth(cls, auth: SimpleWalletCredentials) -> None:
        cls.remove_challenge(auth.address, auth.chain)
        if auth.token:
            cls.__auths.pop(auth.token)

    @classmethod
    def unregister_token(cls, token: str) -> None:
        auth = cls.__auths.get(token)
        if auth:
            cls.unregister_auth(auth)

    @classmethod
    def unregister_expired(cls) -> None:
        now = int(time.time())
        for challenge in cls.__challenges.values():
            if now > challenge.valid_til:
                cls.unregister_auth(challenge)

    @classmethod
    def refresh_token(
        cls, token: str, ttl: int = settings.TOKEN_TTL
    ) -> SimpleWalletCredentials:
        auth = cls.get_auth_by_token(token)
        cls.unregister_auth(auth)
        auth.refresh_token(ttl)
        assert auth.token
        cls.__auths[auth.token] = auth
        return auth


class JWTCredentialsManager(CredentialsManager[JWTWalletCredentials]):
    """
    This manager is simpler than the `ServerSideCredentialsManager` because it does not need to keep track of
    authentication tokens thanks to JWT validation. It only needs to keep track of the challenges.
    """

    credentials_type = JWTWalletCredentials

    @classmethod
    def get_auth_by_token(cls, token: str) -> JWTWalletCredentials:
        return JWTWalletCredentials.from_token(token)

    @classmethod
    def refresh_token(cls, token: str, ttl: int = settings.TOKEN_TTL):
        auth = cls.get_auth_by_token(token)
        auth.refresh_token(ttl)
        return auth
