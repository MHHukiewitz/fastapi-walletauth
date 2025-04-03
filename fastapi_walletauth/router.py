from fastapi import APIRouter, HTTPException
from typing import Optional

from .common import NotAuthorizedError, SupportedChains
from .credentials import WalletCredentialsInfo
from .manager import (
    CredentialsManager,
    JWTCredentialsManager,
    ServerSideCredentialsManager,
    JWTTransactionCredentialsManager,
    ServerSideTransactionCredentialsManager,
)
from .verification import BadSignatureError


class ChallengeResponse(WalletCredentialsInfo):
    challenge: str


class TokenResponse(WalletCredentialsInfo):
    token: str


class TransactionChallengeResponse(WalletCredentialsInfo):
    """Response model for transaction challenge"""
    transaction: str


def create_authorization_router(credentials_manager: CredentialsManager) -> APIRouter:
    routes = APIRouter(
        prefix="/authorization",
        tags=["authorization"],
        responses={404: {"description": "Not found"}},
    )

    @routes.post("/challenge")
    async def create_challenge(
        address: str, chain: SupportedChains, greeting: Optional[str] = None
    ) -> ChallengeResponse:
        challenge = credentials_manager.get_challenge(address=address, chain=chain, greeting=greeting)
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
                token=auth.token if auth.token is not None else "",
                valid_til=auth.valid_til,
            )
        except (BadSignatureError, ValueError) as e:
            raise HTTPException(403, f"Challenge failed: {str(e)}")
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
            address=auth.address,
            chain=auth.chain,
            token=auth.token if auth.token is not None else "",
            valid_til=auth.valid_til,
        )

    if isinstance(credentials_manager, ServerSideCredentialsManager):

        @routes.post("/logout")
        async def logout(token: str):
            credentials_manager.unregister_token(token)
            return {"message": "Logged out"}

    return routes


def create_transaction_authorization_router(use_jwt: bool = True) -> APIRouter:
    """
    Creates a router for transaction-based authentication.
    
    Args:
        use_jwt: Whether to use JWT tokens (True) or server-side tokens (False)
        
    Returns:
        A FastAPI router with transaction challenge endpoints
    """
    manager = JWTTransactionCredentialsManager if use_jwt else ServerSideTransactionCredentialsManager
    
    router = APIRouter(
        prefix="/transaction-auth",
        tags=["authorization"],
        responses={404: {"description": "Not found"}}
    )
    
    @router.post("/challenge")
    async def create_transaction_challenge(
        address: str, chain: SupportedChains, greeting: Optional[str] = None
    ) -> TransactionChallengeResponse:
        """
        Create a transaction challenge for the given address and chain.
        
        Args:
            address: The wallet address
            chain: The blockchain to use
            greeting: Optional greeting message
            
        Returns:
            A transaction challenge response
        """
        auth = manager.get_transaction_challenge(address=address, chain=chain, greeting=greeting)
        return TransactionChallengeResponse(
            address=auth.address,
            chain=auth.chain,
            valid_til=auth.valid_til,
            transaction=auth.transaction
        )
    
    @router.post("/solve")
    async def solve_transaction_challenge(
        address: str, chain: SupportedChains, signature: str, transaction: str
    ) -> TokenResponse:
        """
        Solve a transaction challenge.
        
        Args:
            address: The wallet address
            chain: The blockchain
            signature: The transaction signature
            transaction: The signed transaction
            
        Returns:
            A token response
        """
        try:
            auth = manager.solve_transaction_challenge(
                address=address, chain=chain, signature=signature, transaction=transaction
            )
            return TokenResponse(
                address=auth.address,
                chain=auth.chain,
                token=auth.token if auth.token is not None else "",
                valid_til=auth.valid_til
            )
        except (BadSignatureError, ValueError) as e:
            raise HTTPException(403, f"Challenge failed: {str(e)}")
        except TimeoutError:
            raise HTTPException(403, "Challenge timeout")
    
    @router.post("/refresh")
    async def refresh_token(token: str) -> TokenResponse:
        """
        Refresh a token.
        
        Args:
            token: The token to refresh
            
        Returns:
            A token response
        """
        try:
            auth = manager.refresh_token(token)
        except TimeoutError:
            raise HTTPException(403, "Token expired")
        except NotAuthorizedError:
            raise HTTPException(403, "Not authorized")
        return TokenResponse(
            address=auth.address,
            chain=auth.chain,
            token=auth.token if auth.token is not None else "",
            valid_til=auth.valid_til
        )
    
    # Add logout functionality if it's a server-side manager
    if not use_jwt:
        @router.post("/logout")
        async def logout(token: str):
            manager.unregister_token(token)
            return {"message": "Logged out"}
    
    return router


server_side_authorization_router = create_authorization_router(
    ServerSideCredentialsManager()
)
jwt_authorization_router = create_authorization_router(JWTCredentialsManager())

# Create transaction authorization routers
jwt_transaction_authorization_router = create_transaction_authorization_router(use_jwt=True)
server_transaction_authorization_router = create_transaction_authorization_router(use_jwt=False)
