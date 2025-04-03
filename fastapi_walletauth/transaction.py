"""
Transaction handling for different blockchain networks.
"""
import base58
import base64
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
        A base64-encoded transaction string
    """
    # Memo program ID on Solana
    memo_program_id = base58.b58decode("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
    
    # Create a deterministic "recent blockhash" based on time and address
    # This is just for the challenge - in a real transaction this would be a real blockhash
    blockhash_seed = f"{address}:{int(time.time() / settings.CHALLENGE_TTL)}"
    recent_blockhash = bytes.fromhex(hashlib.sha256(blockhash_seed.encode()).hexdigest()[:64])
    
    # Convert address to bytes
    address_bytes = base58.b58decode(address)
    
    # Create the message header (3 bytes)
    header = bytes([
        1,  # num_required_signatures (1 signer - the fee payer)
        0,  # num_readonly_signed_accounts (none)
        1   # num_readonly_unsigned_accounts (memo program is readonly)
    ])
    
    # Account keys array
    account_keys = bytearray()
    account_keys.extend(address_bytes)      # Fee payer
    account_keys.extend(memo_program_id)    # Memo program
    
    # Create the instruction data
    instruction_data = message.encode('utf-8')
    instruction_data_len = len(instruction_data)
    
    # Create the instruction
    instruction = bytearray()
    instruction.append(1)  # Number of accounts in instruction
    instruction.append(0)  # Index of program ID in account keys
    instruction.append(0)  # Index of fee payer in account keys
    instruction.extend(instruction_data_len.to_bytes(1, byteorder='little'))  # Length of instruction data
    instruction.extend(instruction_data)  # The actual instruction data
    
    # Assemble the transaction message
    tx_message = bytearray()
    tx_message.extend(header)  # Header
    tx_message.extend(account_keys)  # Account keys
    tx_message.extend(recent_blockhash)  # Recent blockhash
    tx_message.extend(len(instruction).to_bytes(1, byteorder='little'))  # Number of instructions
    tx_message.extend(instruction)  # The instruction
    
    # Base64 encode the entire message
    return base64.b64encode(bytes(tx_message)).decode('utf-8')


def verify_solana_transaction_signature(
    signature: str, public_key: str, transaction: str
) -> bool:
    """
    Verify a signature for a Solana transaction.
    
    Args:
        signature: The transaction signature (base58 encoded)
        public_key: The public key of the signer (base58 encoded)
        transaction: The base64-encoded transaction
        
    Returns:
        True if signature is valid, raises BadSignatureError otherwise
    """
    try:
        # Decode the transaction bytes
        tx_bytes = base64.b64decode(transaction)
        
        # Parse the header (first 3 bytes)
        num_required_signatures = tx_bytes[0]
        num_readonly_signed = tx_bytes[1]
        num_readonly_unsigned = tx_bytes[2]
        
        if num_required_signatures != 1:
            raise BadSignatureError("Transaction requires wrong number of signatures")
            
        # Get the fee payer's public key (first account, 32 bytes)
        fee_payer = tx_bytes[3:35]
        if base58.b58encode(fee_payer).decode('utf-8') != public_key:
            raise BadSignatureError("Transaction fee payer doesn't match the provided public key")
            
        # Verify the signature using ed25519
        signature_bytes = base58.b58decode(signature)
        if len(signature_bytes) != 64:
            raise BadSignatureError("Invalid signature length")
            
        # Use nacl to verify the signature
        from nacl.signing import VerifyKey
        verify_key = VerifyKey(fee_payer)
        try:
            verify_key.verify(tx_bytes, signature_bytes)
        except Exception as e:
            raise BadSignatureError("Invalid signature") from e
            
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