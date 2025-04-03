import time
from abc import abstractmethod
from typing import Dict, Generic, Type, Optional, Any

from fastapi_walletauth.common import NotAuthorizedError, SupportedChains, settings
from fastapi_walletauth.credentials import (
    GenericWalletCredentials,
    JWTTransactionWalletCredentials,
    JWTWalletCredentials,
    SimpleTransactionWalletCredentials,
    SimpleWalletCredentials,
    TransactionWalletCredentials
)
from fastapi_walletauth.transaction import create_challenge_transaction, verify_transaction_signature


class CredentialsManager(Generic[GenericWalletCredentials]):
    """
    A self-updating dictionary keeping track of all authentication tokens and signature challenges.
    """

    # Using a single underscore for better subclass access
    _challenges: Dict[str, Any] = {}
    """Keeps track of all solved and unsolved challenges. Keys have format `<address>-<chain>`."""

    credentials_type: Type[GenericWalletCredentials]

    @classmethod
    def get_token(cls, address: str, chain: SupportedChains) -> str:
        key = f"{address}-{chain.value}"
        try:
            auth = cls._challenges.get(key)
            if auth is None or auth.token is None:
                raise NotAuthorizedError("Not authorized")
            return auth.token
        except (TimeoutError, AttributeError) as e:
            if isinstance(e, TimeoutError):
                cls.remove_challenge(address, chain)
            raise NotAuthorizedError("Not authorized") from e

    @classmethod
    def get_challenge(
        cls, address: str, chain: SupportedChains, greeting: Optional[str] = None
    ) -> GenericWalletCredentials:
        key = f"{address}-{chain.value}"
        auth = cls._challenges.get(key)
        if auth is None or int(time.time()) > auth.valid_til:
            auth = cls.credentials_type(address=address, chain=chain, greeting=greeting)
            cls._challenges[key] = auth
        return auth

    @classmethod
    def remove_challenge(cls, address: str, chain: SupportedChains) -> None:
        key = f"{address}-{chain.value}"
        cls._challenges.pop(key, None)

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

    _auths: Dict[str, SimpleWalletCredentials] = {}
    """Maps all authentication tokens to their respective `WalletAuth` objects."""

    credentials_type = SimpleWalletCredentials

    @classmethod
    def get_auth_by_token(cls, token: str) -> SimpleWalletCredentials:
        auth = cls._auths.get(token)
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
        if auth.token:
            cls._auths[auth.token] = auth
        return auth

    @classmethod
    def unregister_auth(cls, auth: SimpleWalletCredentials) -> None:
        cls.remove_challenge(auth.address, auth.chain)
        if auth.token:
            cls._auths.pop(auth.token, None)

    @classmethod
    def unregister_token(cls, token: str) -> None:
        auth = cls._auths.get(token)
        if auth:
            cls.unregister_auth(auth)

    @classmethod
    def unregister_expired(cls) -> None:
        now = int(time.time())
        # Create a list to avoid dict size changing during iteration
        for challenge in list(cls._challenges.values()):
            if now > challenge.valid_til:
                cls.unregister_auth(challenge)

    @classmethod
    def refresh_token(
        cls, token: str, ttl: int = settings.TOKEN_TTL
    ) -> SimpleWalletCredentials:
        auth = cls.get_auth_by_token(token)
        cls.unregister_auth(auth)
        auth.refresh_token(ttl)
        if auth.token:
            cls._auths[auth.token] = auth
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
    def refresh_token(cls, token: str, ttl: int = settings.TOKEN_TTL) -> JWTWalletCredentials:
        auth = cls.get_auth_by_token(token)
        auth.refresh_token(ttl)
        return auth


# Transaction-based Credential Managers

class ServerSideTransactionCredentialsManager:
    """
    Server-side credentials manager that supports transaction-based challenges.
    """
    
    _challenges: Dict[str, SimpleTransactionWalletCredentials] = {}
    _auths: Dict[str, SimpleTransactionWalletCredentials] = {}
    credentials_type = SimpleTransactionWalletCredentials
    
    @classmethod
    def get_token(cls, address: str, chain: SupportedChains) -> str:
        key = f"{address}-{chain.value}"
        try:
            auth = cls._challenges.get(key)
            if auth is None or auth.token is None:
                raise NotAuthorizedError("Not authorized")
            return auth.token
        except (TimeoutError, AttributeError) as e:
            if isinstance(e, TimeoutError):
                cls.remove_challenge(address, chain)
            raise NotAuthorizedError("Not authorized") from e
    
    @classmethod
    def get_transaction_challenge(
        cls, address: str, chain: SupportedChains, greeting: Optional[str] = None
    ) -> SimpleTransactionWalletCredentials:
        """Creates or retrieves a transaction challenge."""
        key = f"{address}-{chain.value}"
        auth = cls._challenges.get(key)
        if auth is None or int(time.time()) > auth.valid_til:
            # Create a new challenge
            valid_til = int(time.time()) + settings.CHALLENGE_TTL
            auth = cls.credentials_type(address=address, chain=chain, greeting=greeting, valid_til=valid_til)
            
            # Generate the transaction that contains the challenge
            transaction = create_challenge_transaction(address, chain, auth.challenge)
            auth.transaction = transaction
            
            cls._challenges[key] = auth
        return auth
    
    @classmethod
    def remove_challenge(cls, address: str, chain: SupportedChains) -> None:
        """Removes a challenge by address and chain."""
        key = f"{address}-{chain.value}"
        cls._challenges.pop(key, None)
    
    @classmethod
    def solve_transaction_challenge(
        cls, address: str, chain: SupportedChains, signature: str, transaction: str
    ) -> SimpleTransactionWalletCredentials:
        """Solves a transaction-based challenge."""
        auth = cls.get_transaction_challenge(address, chain)
        
        # First verify the transaction matches what we sent
        if auth.transaction != transaction:
            raise ValueError("Transaction mismatch")
            
        # Then verify the signature
        verify_transaction_signature(signature, address, transaction, chain)
        
        # If verification passes, solve the challenge
        auth.solve_transaction_challenge(signature, transaction)
        
        # Register the token
        if auth.token:
            cls._auths[auth.token] = auth
        return auth
    
    @classmethod
    def get_auth_by_token(cls, token: str) -> SimpleTransactionWalletCredentials:
        """Gets authentication data by token."""
        auth = cls._auths.get(token)
        if not auth:
            raise NotAuthorizedError("Not authorized")
        if auth.expired:
            cls.remove_challenge(address=auth.address, chain=auth.chain)
            raise TimeoutError("Token expired")
        return auth
    
    @classmethod
    def unregister_auth(cls, auth: SimpleTransactionWalletCredentials) -> None:
        """Unregisters an auth credential."""
        cls.remove_challenge(auth.address, auth.chain)
        if auth.token:
            cls._auths.pop(auth.token, None)
    
    @classmethod
    def unregister_token(cls, token: str) -> None:
        """Unregisters a token."""
        auth = cls._auths.get(token)
        if auth:
            cls.unregister_auth(auth)
    
    @classmethod
    def unregister_expired(cls) -> None:
        """Unregisters all expired challenges."""
        now = int(time.time())
        # Create a list to avoid dict size changing during iteration
        for challenge in list(cls._challenges.values()):
            if now > challenge.valid_til:
                cls.unregister_auth(challenge)
    
    @classmethod
    def refresh_token(
        cls, token: str, ttl: int = settings.TOKEN_TTL
    ) -> SimpleTransactionWalletCredentials:
        """Refreshes a token, creating a new one with extended validity."""
        auth = cls.get_auth_by_token(token)
        # Keep track of the old validity time for comparison
        old_valid_til = auth.valid_til
        
        # Unregister the old token
        cls.unregister_auth(auth)
        
        # Set a new expiration time that's guaranteed to be in the future
        new_valid_til = int(time.time()) + ttl
        # Only update if extending the validity
        if new_valid_til > old_valid_til:
            auth.valid_til = new_valid_til
        
        # Generate a new token
        auth.refresh_token(ttl)
        
        # Register the new token
        if auth.token:
            cls._auths[auth.token] = auth
        return auth


class JWTTransactionCredentialsManager:
    """
    JWT-based credentials manager that supports transaction-based challenges.
    """
    
    _challenges: Dict[str, JWTTransactionWalletCredentials] = {}
    credentials_type = JWTTransactionWalletCredentials
    
    @classmethod
    def get_token(cls, address: str, chain: SupportedChains) -> str:
        key = f"{address}-{chain.value}"
        try:
            auth = cls._challenges.get(key)
            if auth is None or auth.token is None:
                raise NotAuthorizedError("Not authorized")
            return auth.token
        except (TimeoutError, AttributeError) as e:
            if isinstance(e, TimeoutError):
                cls.remove_challenge(address, chain)
            raise NotAuthorizedError("Not authorized") from e
    
    @classmethod
    def get_transaction_challenge(
        cls, address: str, chain: SupportedChains, greeting: Optional[str] = None
    ) -> JWTTransactionWalletCredentials:
        """Creates or retrieves a transaction challenge."""
        key = f"{address}-{chain.value}"
        auth = cls._challenges.get(key)
        if auth is None or int(time.time()) > auth.valid_til:
            # Create a new challenge
            valid_til = int(time.time()) + settings.CHALLENGE_TTL
            auth = cls.credentials_type(address=address, chain=chain, greeting=greeting, valid_til=valid_til)
            
            # Generate the transaction that contains the challenge
            transaction = create_challenge_transaction(address, chain, auth.challenge)
            auth.transaction = transaction
            
            cls._challenges[key] = auth
        return auth
    
    @classmethod
    def remove_challenge(cls, address: str, chain: SupportedChains) -> None:
        """Removes a challenge by address and chain."""
        key = f"{address}-{chain.value}"
        cls._challenges.pop(key, None)
    
    @classmethod
    def solve_transaction_challenge(
        cls, address: str, chain: SupportedChains, signature: str, transaction: str
    ) -> JWTTransactionWalletCredentials:
        """Solves a transaction-based challenge."""
        auth = cls.get_transaction_challenge(address, chain)
        
        # First verify the transaction matches what we sent
        if auth.transaction != transaction:
            raise ValueError("Transaction mismatch")
            
        # Then verify the signature
        verify_transaction_signature(signature, address, transaction, chain)
        
        # If verification passes, solve the challenge
        auth.solve_transaction_challenge(signature, transaction)
        return auth
    
    @classmethod
    def get_auth_by_token(cls, token: str) -> JWTTransactionWalletCredentials:
        """Gets authentication data by token."""
        return JWTTransactionWalletCredentials.from_token(token)
    
    @classmethod
    def refresh_token(
        cls, token: str, ttl: int = settings.TOKEN_TTL
    ) -> JWTTransactionWalletCredentials:
        """Refreshes a token, creating a new one with extended validity."""
        auth = cls.get_auth_by_token(token)
        # Set a new expiration time in the future
        new_valid_til = int(time.time()) + ttl
        # Only update if the new expiration is later
        if new_valid_til > auth.valid_til:
            auth.valid_til = new_valid_til
            # Generate a new token with the updated expiration
            auth.refresh_token(ttl)
        return auth
