"""
Authentication (signing/verification) step of the PGP scheme.

Signing: SHA-1 hash of the message, RSA signature over that hash with the
sender's private key.

The signature packet:
    timestamp,
    the signer's key id (least significant 64 bits),
    the leading two octets of the digest,
    signature itself.

Verifying: recompute the SHA-1 hash of the received message and check the RSA
signature with the sender's public key.

sign/verify work on the SignedMessage structure;
toBytes/fromBytes turn it into the flat byte stream that the rest of the pipeline passes forward.
"""

import struct
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from pgp_messages import SignedMessage


class AuthenticationService:
    def sign(self, msg: bytes, privateKeyPem: bytes, password: bytes = None) -> SignedMessage:
        privateKey = serialization.load_pem_private_key(privateKeyPem, password=password)
        assert isinstance(privateKey, RSAPrivateKey)

        # SHA-1 digest computed once, reused for both the leading octets and the signature
        digest = hashes.Hash(hashes.SHA1())
        digest.update(msg)
        hash_value = digest.finalize()

        signature = privateKey.sign(
            hash_value,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA1()),
        )

        # keyId = least significant 64 bits of the modulus (same rule as encrypt_message.py)
        public_key = privateKey.public_key()
        modulus = public_key.public_numbers().n
        key_id = (modulus % (2 ** 64)).to_bytes(8, "big")

        result = SignedMessage()
        result.rawMessage = msg
        result.signature = signature
        result.leadingTwoOctets = hash_value[:2]
        result.keyId = key_id
        result.timestamp = datetime.now(timezone.utc)
        return result

    def verify(self, message: SignedMessage, publicKeyPem: bytes) -> bool:
        public_key = serialization.load_pem_public_key(publicKeyPem)

        digest = hashes.Hash(hashes.SHA1())
        digest.update(message.rawMessage)
        hash_value = digest.finalize()

        # fast fail
        if hash_value[:2] != message.leadingTwoOctets:
            return False

        try:
            public_key.verify(
                message.signature,
                hash_value,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA1()),
            )
            return True
        except InvalidSignature:
            return False


def toBytesFromSignedMessage(message: SignedMessage) -> bytes:
    timestamp = int(message.timestamp.timestamp())
    return (
        struct.pack(">IHH", timestamp, len(message.keyId), len(message.signature))
        + message.leadingTwoOctets            # fiksno 2 bajta
        + message.keyId
        + message.signature
        + message.rawMessage                  # ostatak
    )


def fromBytesToSignedMessage(data: bytes) -> SignedMessage:
    timestamp, keyIdLen, signatureLen = struct.unpack(">IHH", data[:8])
    offset = 8

    leadingTwoOctets = data[offset:offset + 2]
    offset += 2

    keyId = data[offset:offset + keyIdLen]
    offset += keyIdLen

    signature = data[offset:offset + signatureLen]
    offset += signatureLen

    result = SignedMessage()
    result.timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    result.leadingTwoOctets = leadingTwoOctets
    result.keyId = keyId
    result.signature = signature
    result.rawMessage = data[offset:]
    return result