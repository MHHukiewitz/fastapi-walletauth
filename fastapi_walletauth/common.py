from enum import Enum
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseSettings


class SupportedChains(Enum):
    Solana = "SOL"
    Ethereum = "ETH"


class AuthType(Enum):
    Bearer = "Bearer"
    JWT = "JWT"


class NotAuthorizedError(Exception):
    pass


class Settings(BaseSettings):
    APP = "fastapi_walletauth"
    PRIVATE_KEY = Ed25519PrivateKey.generate().private_bytes_raw()
    AUTH_TYPE = AuthType.JWT
    TOKEN_TTL = 24 * 60 * 60  # 24 hours
    CHALLENGE_TTL = 10 * 60  # 10 minutes

    class Config:
        env_prefix = "FASTAPI_WALLETAUTH_"
        case_sensitive = False
        env_file = ".env"


settings = Settings()
