"""
Transaction handling for different blockchain networks.
"""
import base58
import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple, Union

from fastapi_walletauth.common import SupportedChains, settings
from fastapi_walletauth.verification import BadSignatureError


class TransactionError(Exception):
    """Exception raised for transaction-related errors."""
    pass


def create_solana_memo_transaction(address: str, message: str) -> str:
    """
    Create a simple Solana memo transaction with the challenge message.
    
    Args:
        address: The wallet address that will sign this transaction
        message: The challenge message to include in the memo
        
    Returns:
        A base58-encoded transaction string
    """
    # Create a simplified transaction structure that includes:
    # 1. A memo program instruction
    # 2. The address as the fee payer and signer
    # 3. The current blockhash (mocked for challenge purposes)
    # 4. The challenge message as memo data
    
    # Memo program ID on Solana
    memo_program_id = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
    
    # Create a deterministic "recent blockhash" based on time and address
    # This is just for the challenge - in a real transaction this would be a real blockhash
    blockhash_seed = f"{address}:{int(time.time() / settings.CHALLENGE_TTL)}"
    recent_blockhash = hashlib.sha256(blockhash_seed.encode()).hexdigest()[:32]
    
    # Basic transaction structure
    transaction = {
        "recentBlockhash": recent_blockhash,
        "feePayer": address,
        "instructions": [
            {
                "programId": memo_program_id,
                "keys": [],  # Memo doesn't need any keys
                "data": base58.b58encode(message.encode()).decode("utf-8")
            }
        ],
        "signers": [address]
    }
    
    # Convert to JSON and then base58 encode
    tx_json = json.dumps(transaction)
    tx_bytes = tx_json.encode("utf-8")
    tx_encoded = base58.b58encode(tx_bytes).decode("utf-8")
    
    return tx_encoded


def verify_solana_transaction_signature(
    signature: str, public_key: str, transaction: str
) -> bool:
    """
    Verify a signature for a Solana transaction.
    
    Args:
        signature: The transaction signature
        public_key: The public key of the signer
        transaction: The base58-encoded transaction
        
    Returns:
        True if signature is valid, raises BadSignatureError otherwise
    """
    # This is a simplified implementation
    # In a real implementation, we would:
    # 1. Decode the transaction
    # 2. Verify the signature on the transaction data
    # 3. Verify that the signer is the expected wallet
    
    try:
        # Parse the transaction data 
        tx_bytes = base58.b58decode(transaction)
        tx_data = json.loads(tx_bytes.decode("utf-8"))
        
        # Verify the transaction structure
        if not tx_data.get("instructions") or len(tx_data["instructions"]) == 0:
            raise BadSignatureError("Invalid transaction: no instructions found")
            
        # Verify the fee payer matches the public key
        if tx_data.get("feePayer") != public_key:
            raise BadSignatureError("Transaction feePayer doesn't match the provided public key")
            
        # In a real implementation, we would verify the signature cryptographically
        # For now we'll just check if the signature is present and has the expected format
        
        if not signature or not signature.startswith("0x") and not len(base58.b58decode(signature)) == 64:
            raise BadSignatureError("Invalid signature format")
            
        # For a proper implementation, we would use:
        # from nacl.signing import VerifyKey
        # VerifyKey(public_key_bytes).verify(tx_bytes, signature_bytes)
        
        return True
        
    except Exception as e:
        raise BadSignatureError(f"Failed to verify transaction signature: {str(e)}")


def create_ethereum_transaction(address: str, message: str) -> str:
    """
    Create a simplified Ethereum transaction with the challenge message.
    
    Args:
        address: The wallet address that will sign this transaction
        message: The challenge message
        
    Returns:
        A hex-encoded transaction string
    """
    # For Ethereum, create a simple transaction structure
    # This is a simplified mock - in a real app you'd use web3.py to create proper transactions
    
    # Create a deterministic nonce based on time and address
    nonce_seed = f"{address}:{int(time.time() / settings.CHALLENGE_TTL)}"
    nonce = int(hashlib.sha256(nonce_seed.encode()).hexdigest(), 16) % 10000
    
    # Basic transaction with a data field containing our message
    transaction = {
        "from": address,
        "to": "0x0000000000000000000000000000000000000000",  # Zero address
        "value": "0x0",
        "gas": "0x5208",  # 21000
        "gasPrice": "0x1",
        "nonce": hex(nonce),
        "data": "0x" + message.encode().hex(),
        "chainId": 1  # Mainnet
    }
    
    # Convert to JSON and then hex encode
    tx_json = json.dumps(transaction)
    tx_bytes = tx_json.encode("utf-8")
    tx_encoded = "0x" + tx_bytes.hex()
    
    return tx_encoded


def verify_ethereum_transaction_signature(
    signature: str, public_key: str, transaction: str
) -> bool:
    """
    Verify a signature for an Ethereum transaction.
    
    Args:
        signature: The transaction signature (hex encoded)
        public_key: The public key (address) of the signer
        transaction: The hex-encoded transaction
        
    Returns:
        True if signature is valid, raises BadSignatureError otherwise
    """
    # This is a simplified implementation
    # In a real implementation, we would:
    # 1. Decode the transaction
    # 2. Verify the signature using web3.py and eth_account
    
    try:
        # Basic format checks
        if not signature or not signature.startswith("0x"):
            raise BadSignatureError("Invalid signature format")
            
        # Decode the transaction
        if not transaction or not transaction.startswith("0x"):
            raise BadSignatureError("Invalid transaction format")
            
        tx_bytes = bytes.fromhex(transaction[2:])
        tx_data = json.loads(tx_bytes.decode("utf-8"))
        
        # Verify the transaction sender
        if tx_data.get("from", "").lower() != public_key.lower():
            raise BadSignatureError("Transaction sender doesn't match the provided public key")
        
        # For a proper implementation, we would use:
        # from eth_account import Account
        # Account.recover_transaction(transaction, signature)
        
        return True
        
    except Exception as e:
        raise BadSignatureError(f"Failed to verify transaction signature: {str(e)}")


def create_challenge_transaction(address: str, chain: SupportedChains, message: str) -> str:
    """
    Create a challenge transaction for the specified chain.
    
    Args:
        address: The wallet address
        chain: The blockchain to use
        message: The challenge message to include in the transaction
        
    Returns:
        A chain-specific encoded transaction string
    """
    if chain.value == SupportedChains.Solana.value:
        return create_solana_memo_transaction(address, message)
    elif chain.value == SupportedChains.Ethereum.value:
        return create_ethereum_transaction(address, message)
    else:
        raise NotImplementedError(f"{chain} has no transaction implementation")


def verify_transaction_signature(
    signature: str, public_key: str, transaction: str, chain: SupportedChains
) -> bool:
    """
    Verify a transaction signature for the specified chain.
    
    Args:
        signature: The transaction signature
        public_key: The public key of the signer
        transaction: The encoded transaction
        chain: The blockchain used
        
    Returns:
        True if signature is valid, raises BadSignatureError otherwise
    """
    if chain.value == SupportedChains.Solana.value:
        return verify_solana_transaction_signature(signature, public_key, transaction)
    elif chain.value == SupportedChains.Ethereum.value:
        return verify_ethereum_transaction_signature(signature, public_key, transaction)
    else:
        raise NotImplementedError(f"{chain} has no transaction verification implemented") 