from typing import Type

from fastapi import APIRouter, HTTPException

from .manager import ServerSideCredentialsManager, CredentialsManager, JWTCredentialsManager
from .common import SupportedChains, NotAuthorizedError
from .credentials import WalletCredentialsInfo
from .verification import BadSignatureError


class ChallengeResponse(WalletCredentialsInfo):
    challenge: str


class TokenResponse(WalletCredentialsInfo):
    token: str


def create_authorization_routes(credentials_manager: Type[CredentialsManager]) -> APIRouter:
    routes = APIRouter(
        prefix="/authorization",
        tags=["authorization"],
        responses={404: {"description": "Not found"}},
    )

    @routes.post("/challenge")
    async def create_challenge(
        address: str, chain: SupportedChains
    ) -> ChallengeResponse:
        challenge = credentials_manager.get_auth_by_wallet(address=address, chain=chain)
        return ChallengeResponse(
            address=challenge.address,
            chain=challenge.chain,
            challenge=challenge.challenge,
            valid_til=challenge.valid_til,
        )

    @routes.post("/solve")
    async def solve_challenge(
        address: str, chain: SupportedChains, signature: str
    ) -> TokenResponse:
        try:
            auth = credentials_manager.solve_challenge(
                address=address, chain=chain, signature=signature
            )
            return TokenResponse(
                address=auth.address,
                chain=auth.chain,
                token=auth.token,
                valid_til=auth.valid_til,
            )
        except (BadSignatureError, ValueError):
            raise HTTPException(403, "Challenge failed")
        except TimeoutError:
            raise HTTPException(403, "Challenge timeout")

    @routes.post("/refresh")
    async def refresh_token(token: str) -> TokenResponse:
        try:
            auth = credentials_manager.refresh_token(token)
        except TimeoutError:
            raise HTTPException(403, "Token expired")
        except NotAuthorizedError:
            raise HTTPException(403, "Not authorized")
        return TokenResponse(
            address=auth.address, chain=auth.chain, token=auth.token, valid_til=auth.valid_til
        )

    if issubclass(credentials_manager, ServerSideCredentialsManager):
        @routes.post("/logout")
        async def logout(token: str):
            credentials_manager.unregister_token(token)
            return {"message": "Logged out"}

    return routes


server_side_authorization_routes = create_authorization_routes(ServerSideCredentialsManager)
jwt_authorization_routes = create_authorization_routes(JWTCredentialsManager)
