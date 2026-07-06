"""
For the encryption we need 2 algorythms, we will use: TripleDES, AES128
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from pgp_messages import EncryptedMessage, AlgorithmSymmetric
import os
import struct

ALGORITHM_CODES = {AlgorithmSymmetric.AES: 0, AlgorithmSymmetric.DES3: 1}
ALGORITHM_FROM_CODE = {code: algo for algo, code in ALGORITHM_CODES.items()}

class EncryptionService:
    def encrypt(self, msg: bytes, PU: bytes, algorythm: AlgorithmSymmetric) -> EncryptedMessage:
        publicKey = serialization.load_pem_public_key(PU)

        # generation of session key

        if algorythm == AlgorithmSymmetric.AES:
            sessionKey = os.urandom(16)
        elif algorythm == AlgorithmSymmetric.DES3:
            sessionKey = os.urandom(24)

        # encryption of message

        if algorythm == AlgorithmSymmetric.AES:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(sessionKey), modes.CFB(iv))
        elif algorythm == AlgorithmSymmetric.DES3:
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
        result.iv = iv
        result.keyId = keyId
        result.algorythm = algorythm
        return result

    def decrypt(self, msg: EncryptedMessage, PR: bytes) -> bytes:
        privateKey = serialization.load_pem_private_key(PR, password=None)

        # decryption of session key

        sessionKey = privateKey.decrypt(msg.encryptedSessionKey, rsa_padding.PKCS1v15())

        # decryption of message

        if msg.algorythm == AlgorithmSymmetric.AES:
            cipher = Cipher(algorithms.AES(sessionKey), modes.CFB(msg.iv))
        elif msg.algorythm == AlgorithmSymmetric.DES3:
            cipher = Cipher(algorithms.TripleDES(sessionKey), modes.CFB(msg.iv))

        decryptor = cipher.decryptor()
        msgDecrypted = decryptor.update(msg.msg[len(msg.iv):]) + decryptor.finalize()

        return msgDecrypted
    
def toBytesFromEncryptedMessage(message: EncryptedMessage) -> bytes:
    algorithmCode = ALGORITHM_CODES[message.algorythm]

    return (
        struct.pack(
            ">BHH",
            algorithmCode,
            len(message.keyId),
            len(message.iv),
        )
        + message.keyId
        + message.iv
        + struct.pack(">I", len(message.encryptedSessionKey))
        + message.encryptedSessionKey
        + message.msg
    )

def fromBytesToEncryptedMessage(data: bytes) -> EncryptedMessage:
    algorithmCode, keyIdLen, ivLen = struct.unpack(">BHH", data[:5])
    offset = 5

    keyId = data[offset:offset + keyIdLen]
    offset += keyIdLen

    iv = data[offset:offset + ivLen]
    offset += ivLen

    encryptedSessionKeyLen = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4

    encryptedSessionKey = data[offset:offset + encryptedSessionKeyLen]
    offset += encryptedSessionKeyLen

    result = EncryptedMessage()
    result.algorythm = ALGORITHM_FROM_CODE[algorithmCode]
    result.keyId = keyId
    result.iv = iv
    result.encryptedSessionKey = encryptedSessionKey
    result.msg = data[offset:]
    return result