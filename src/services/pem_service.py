"""
Functions for generating, importing and exporting PEM encoded RSA key pairs.
A key pair file holds the private key (its public key can always be derived
from it); a public-only file holds just the public key.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_KEY_SIZE = 2048
DEFAULT_PUBLIC_EXPONENT = 65537

class PEMService:
    def __init__(self, key_size: int = DEFAULT_KEY_SIZE, public_exponent: int = DEFAULT_PUBLIC_EXPONENT):
        if key_size <= 0:
            raise ValueError("maxSize must be a positive number of bytes")
        if public_exponent <= 0 or public_exponent >= (1 << (key_size + 1)):
            raise ValueError("public_exponent must be a positive number and less then default key size limits")
        self.key_size = key_size
        self.public_exponent = public_exponent

    def generateKeyPair(self) -> tuple[bytes, bytes]:
        privateKey = rsa.generate_private_key(
            public_exponent=self.public_exponent,
            key_size=self.key_size
        )

        privatePem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        publicPem = privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return privatePem, publicPem

    def importFromFile(self, path: str) -> tuple[bytes | None, bytes]:
        with open(path, "rb") as file:
            data = file.read()

        try:
            # load_pem_private_key finds the private key block even if a
            # public key block is also present further down in the file
            privateKey = serialization.load_pem_private_key(data, password=None)
        except ValueError:
            # no private key block, so the file must hold a public key only
            serialization.load_pem_public_key(data)
            return None, data

        privatePem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        publicPem = privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return privatePem, publicPem

    def exportToFile(self, path: str, privateKeyPem: bytes | None, publicKeyPem: bytes) -> None:
        # write both PEM blocks for a key pair, so the file is human-readable
        # on its own even though the public key is derivable from the private one
        data = privateKeyPem + b"\n" + publicKeyPem if privateKeyPem is not None else publicKeyPem
        with open(path, "wb") as file:
            file.write(data)
