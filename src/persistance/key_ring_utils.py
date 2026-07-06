from cryptography.hazmat.primitives import serialization

def keyIdFromPublicKeyPem(publicKeyPem: bytes) -> bytes:
    """keyId = least significant 64 bits of the modulus (same rule used
    throughout the scheme, e.g. authentication_service.sign)."""
    publicKey = serialization.load_pem_public_key(publicKeyPem)
    modulus = publicKey.public_numbers().n
    return (modulus % (2 ** 64)).to_bytes(8, "big")
