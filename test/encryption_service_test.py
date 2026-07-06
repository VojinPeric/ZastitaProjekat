"""
pytest tests for EncryptionService.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pgp_messages import EncryptedMessage, AlgorithmSymmetric
from encryption_service import (
    EncryptionService,
    toBytesFromEncryptedMessage,
    fromBytesToEncryptedMessage,
)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def enc():
    """A fresh service for each test."""
    return EncryptionService()


@pytest.fixture
def make_key_pair():
    """
    Returns a function so a single test can make several
    """
    def _make(bits=1024):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)

        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    return _make


@pytest.fixture
def key_pair(make_key_pair):
    """The common case: one default (private, public) pair."""
    return make_key_pair()


def modulus_of(public_pem):
    return serialization.load_pem_public_key(public_pem).public_numbers().n


# ---------------------------------------------------------------------------
# encrypt / decrypt round trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("algorithm", [AlgorithmSymmetric.AES, AlgorithmSymmetric.DES3])
def test_encrypt_decrypt_round_trip(enc, key_pair, algorithm):
    priv, pub = key_pair
    msg = b"hello world"

    encrypted = enc.encrypt(msg, pub, algorithm)

    assert enc.decrypt(encrypted, priv) == msg


def test_empty_message_round_trips(enc, key_pair):
    priv, pub = key_pair

    encrypted = enc.encrypt(b"", pub, AlgorithmSymmetric.AES)

    assert enc.decrypt(encrypted, priv) == b""


# ---------------------------------------------------------------------------
# structure of the encrypted message
# ---------------------------------------------------------------------------

def test_encrypt_populates_all_fields(enc, key_pair):
    _, pub = key_pair
    msg = b"structure check"

    encrypted = enc.encrypt(msg, pub, AlgorithmSymmetric.AES)

    assert isinstance(encrypted, EncryptedMessage)
    assert encrypted.algorythm == AlgorithmSymmetric.AES
    assert len(encrypted.iv) == 16
    assert len(encrypted.keyId) == 8
    assert len(encrypted.encryptedSessionKey) > 0
    assert encrypted.msg != msg  # ciphertext, not plaintext


def test_des3_uses_8_byte_iv(enc, key_pair):
    _, pub = key_pair

    encrypted = enc.encrypt(b"triple des", pub, AlgorithmSymmetric.DES3)

    assert len(encrypted.iv) == 8


def test_keyid_is_least_significant_64_bits(enc, key_pair):
    _, pub = key_pair

    encrypted = enc.encrypt(b"anything", pub, AlgorithmSymmetric.AES)

    expected = (modulus_of(pub) % (2**64)).to_bytes(8, "big")
    assert encrypted.keyId == expected


def test_encrypting_twice_uses_different_session_key_and_iv(enc, key_pair):
    """Fresh randomness each call, so ciphertexts of the same message differ."""
    _, pub = key_pair
    msg = b"same message"

    first = enc.encrypt(msg, pub, AlgorithmSymmetric.AES)
    second = enc.encrypt(msg, pub, AlgorithmSymmetric.AES)

    assert first.iv != second.iv
    assert first.encryptedSessionKey != second.encryptedSessionKey
    assert first.msg != second.msg


# ---------------------------------------------------------------------------
# wrong key
# ---------------------------------------------------------------------------

def test_decrypt_with_wrong_private_key_fails(enc, key_pair, make_key_pair):
    _, pub = key_pair
    other_priv, _ = make_key_pair()  # unrelated pair

    encrypted = enc.encrypt(b"secret", pub, AlgorithmSymmetric.AES)

    with pytest.raises(Exception):
        enc.decrypt(encrypted, other_priv)


# ---------------------------------------------------------------------------
# serialization round trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("algorithm", [AlgorithmSymmetric.AES, AlgorithmSymmetric.DES3])
def test_serialization_round_trip_preserves_fields(enc, key_pair, algorithm):
    _, pub = key_pair

    original = enc.encrypt(b"round trip me", pub, algorithm)
    restored = fromBytesToEncryptedMessage(toBytesFromEncryptedMessage(original))

    assert restored.algorythm == original.algorythm
    assert restored.keyId == original.keyId
    assert restored.iv == original.iv
    assert restored.encryptedSessionKey == original.encryptedSessionKey
    assert restored.msg == original.msg


def test_decrypt_still_works_after_round_trip(enc, key_pair):
    priv, pub = key_pair

    original = enc.encrypt(b"survive the wire", pub, AlgorithmSymmetric.AES)
    restored = fromBytesToEncryptedMessage(toBytesFromEncryptedMessage(original))

    assert enc.decrypt(restored, priv) == b"survive the wire"


def test_fromBytes_rejects_truncated_data():
    """Header needs 5 bytes; anything shorter must blow up rather than parse
    into garbage."""
    with pytest.raises(Exception):
        fromBytesToEncryptedMessage(b"\x00\x01")
