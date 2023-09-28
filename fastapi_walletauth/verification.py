from typing import Union

import base58
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys.exceptions import BadSignature as EthBadSignatureError
from nacl.exceptions import BadSignatureError as NaclBadSignatureError
from nacl.signing import VerifyKey


class BadSignatureError(Exception):
    """
    The signature of a message is invalid.
    """

    pass


def verify_signature_sol(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
):
    """
    Verifies a signature.
    Args:
        signature: The signature to verify. Can be a base58 encoded string or bytes.
        public_key: The public key to use for verification. Can be a base58 encoded string or bytes.
        message: The message to verify. Can be an utf-8 string or bytes.
    Raises:
        BadSignatureError: If the signature is invalid.
    """
    if isinstance(signature, str):
        if signature.startswith("0x"):
            signature = signature[2:]
            signature = bytes.fromhex(signature)
        else:
            signature = base58.b58decode(signature)
    if isinstance(message, str):
        message = message.encode("utf-8")
    if isinstance(public_key, str):
        public_key = base58.b58decode(public_key)
    try:
        VerifyKey(public_key).verify(message, signature)
    except NaclBadSignatureError as e:
        raise BadSignatureError from e


def verify_signature_eth(
    signature: Union[bytes, str],
    public_key: Union[bytes, str],
    message: Union[bytes, str],
):
    """
    Verifies a signature.
    Args:
        signature: The signature to verify. Can be a hex encoded string or bytes.
        public_key: The sender's public key to use for verification. Can be a checksum, hex encoded string or bytes.
        message: The message to verify. Can be an utf-8 string or bytes.
    Raises:
        BadSignatureError: If the signature is invalid.
    """
    if isinstance(signature, str):
        if signature.startswith("0x"):
            signature = signature[2:]
        signature = bytes.fromhex(signature)
    if isinstance(public_key, bytes):
        public_key = "0x" + public_key.hex()
    if isinstance(message, bytes):
        message = message.decode("utf-8")

    message_hash = encode_defunct(text=message)
    try:
        address = Account.recover_message(message_hash, signature=signature)
        if address.casefold() != public_key.casefold():
            raise BadSignatureError
    except (EthBadSignatureError, BadSignatureError) as e:
        raise BadSignatureError from e
