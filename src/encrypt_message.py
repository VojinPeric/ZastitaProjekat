"""
For the encryption we need 2 algorythms, we will use: TripleDES, AES128
"""

from enum import Enum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from pgp_messages import EncryptedMessage
import os

class Algorithm(Enum):
    AES = "AES128"
    DES3 = "DES3"

def encrypt(msg: bytes, PUb: bytes, algorythm: Algorithm) -> EncryptedMessage:
    publicKey = serialization.load_pem_public_key(PUb)

    # generation of session key

    if algorythm == Algorithm.AES:
        sessionKey = os.urandom(16)
    elif algorythm == Algorithm.DES3:
        sessionKey = os.urandom(24)

    # encryption of message

    if algorythm == Algorithm.AES:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(sessionKey), modes.CFB(iv))
    elif algorythm == Algorithm.DES3:
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(sessionKey), modes.CFB(iv))

    encryptor = cipher.encryptor()
    encryptedMsg = iv + encryptor.update(msg) + encryptor.finalize()

    # encryption of key

    encryptedKey = publicKey.encrypt(sessionKey, rsa_padding.PKCS1v15())

    # returning (ID of key is least significant 64 bits)

    modulus = publicKey.public_numbers().n
    modulusBytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, byteorder="big")
    keyId = modulusBytes[-8:]

    result = EncryptedMessage()
    result.msg = encryptedMsg
    result.encryptedSessionKey = encryptedKey
    result.keyId = keyId
    return result
