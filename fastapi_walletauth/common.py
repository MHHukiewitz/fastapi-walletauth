from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ConfigDict, Extra
from pydantic_settings import BaseSettings


class SupportedChains(Enum):
    Solana = "SOL"
    Ethereum = "ETH"


class AuthType(Enum):
    Bearer = "Bearer"
    JWT = "JWT"


class NotAuthorizedError(Exception):
    pass


class Settings(BaseSettings):
    APP: str = "fastapi_walletauth"
    PRIVATE_KEY: str = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    PUBLIC_KEY: str = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRIVATE_KEY)).public_key().public_bytes_raw().hex()
    AUTH_TYPE: str = AuthType.JWT.value
    TOKEN_TTL: int = 24 * 60 * 60  # 24 hours
    CHALLENGE_TTL: int = 10 * 60  # 10 minutes
    GREETING: str = "Hello, please sign this message!"  # Default greeting

    model_config = ConfigDict(
        env_prefix="FASTAPI_WALLETAUTH_",
        case_sensitive=False,
        env_file=".env",
        extra=Extra.allow
    )


settings = Settings()
