from typing import Annotated, Generic

from fastapi import HTTPException
from fastapi.params import Depends
from fastapi.security import HTTPBearer
from fastapi.security.utils import get_authorization_scheme_param
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from fastapi_walletauth.common import NotAuthorizedError
from fastapi_walletauth.credentials import (
    GenericWalletCredentials,
    JWTWalletCredentials,
    SimpleWalletCredentials,
)
from fastapi_walletauth.manager import (
    CredentialsManager,
    JWTCredentialsManager,
    ServerSideCredentialsManager,
)


class BearerWalletAuth(HTTPBearer, Generic[GenericWalletCredentials]):
    def __init__(
        self,
        manager: CredentialsManager,
        challenge_endpoint: str = "/authorization/challenge",
        token_endpoint: str = "/authorization/solve",
    ):
        self.manager = manager
        self.challenge_endpoint = challenge_endpoint
        self.token_endpoint = token_endpoint
        super().__init__(
            scheme_name="Signature Challenge Token",
            description=f"Authenticate using a challenge solution. "
            f"First, send a POST request to {challenge_endpoint} with your public key and chain. "
            f"Then, sign the challenge and send a POST request to {token_endpoint} with your public key, chain and signature. "
            f"If successful, you will receive a token which you can use to authenticate future requests.",
            auto_error=False,
        )

    async def __call__(self, request: Request) -> GenericWalletCredentials:
        authorization = request.headers.get("Authorization")
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
            )
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid authentication credentials",
            )

        try:
            return self.manager.get_auth_by_token(credentials)
        except (TimeoutError, NotAuthorizedError) as e:
            if e is TimeoutError:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail="Token expired"
                )
            if e is NotAuthorizedError:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail=f"Not authorized. Request a challenge to sign from f{self.challenge_endpoint} "
                    f"and retrieve a token from f{self.token_endpoint}.",
                )
            raise e


jwt_credentials_manager = JWTCredentialsManager()
JWTWalletAuthDep = Annotated[
    JWTWalletCredentials, Depends(BearerWalletAuth(jwt_credentials_manager))
]
server_side_credentials_manager = ServerSideCredentialsManager()
BearerWalletAuthDep = Annotated[
    SimpleWalletCredentials, Depends(BearerWalletAuth(server_side_credentials_manager))
]
