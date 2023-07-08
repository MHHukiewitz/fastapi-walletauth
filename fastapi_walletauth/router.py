from aleph.sdk.exceptions import BadSignatureError
from fastapi import APIRouter, HTTPException

from .core import AuthTokenManager, NotAuthorizedError, SupportedChains, AuthInfo

authorization = APIRouter(
    prefix="/authorization",
    tags=["authorization"],
    responses={404: {"description": "Not found"}},
)


class TokenChallengeResponse(AuthInfo):
    challenge: str


class BearerTokenResponse(AuthInfo):
    token: str


@authorization.post("/challenge")
async def create_challenge(
    address: str, chain: SupportedChains
) -> TokenChallengeResponse:
    challenge = AuthTokenManager.get_challenge(address=address, chain=chain)
    return TokenChallengeResponse(
        address=challenge.address,
        chain=challenge.chain,
        challenge=challenge.challenge,
        valid_til=challenge.valid_til,
    )


@authorization.post("/solve")
async def solve_challenge(
    address: str, chain: SupportedChains, signature: str
) -> BearerTokenResponse:
    try:
        auth = AuthTokenManager.solve_challenge(
            address=address, chain=chain, signature=signature
        )
        return BearerTokenResponse(
            address=auth.address,
            chain=auth.chain,
            token=auth.token,
            valid_til=auth.valid_til,
        )
    except (BadSignatureError, ValueError):
        raise HTTPException(403, "Challenge failed")
    except TimeoutError:
        raise HTTPException(403, "Challenge timeout")


@authorization.post("/refresh")
async def refresh_token(token: str) -> BearerTokenResponse:
    try:
        auth = AuthTokenManager.refresh_token(token)
    except TimeoutError:
        raise HTTPException(403, "Token expired")
    except NotAuthorizedError:
        raise HTTPException(403, "Not authorized")
    return BearerTokenResponse(
        address=auth.address, chain=auth.chain, token=auth.token, valid_til=auth.valid_til
    )


@authorization.post("/logout")
async def logout(token: str):
    AuthTokenManager.remove_token(token)
