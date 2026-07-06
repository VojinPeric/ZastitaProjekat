"""
pytest tests for AuthenticationService.
"""

import hashlib
from datetime import timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pgp_messages import SignedMessage
from authentication_service import (
    AuthenticationService,
    toBytesFromSignedMessage,
    fromBytesToSignedMessage,
)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth():
    """A fresh service for each test."""
    return AuthenticationService()


@pytest.fixture
def make_key_pair():
    """
    Returns a function so a single test can make several
    """
    def _make(bits=1024, password=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)

        if password is None:
            encryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(password)

        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
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
# signing
# ---------------------------------------------------------------------------

def test_sign_populates_all_fields(auth, key_pair):
    priv, _ = key_pair
    msg = b"hello world"

    signed = auth.sign(msg, priv)

    assert isinstance(signed, SignedMessage)
    assert signed.rawMessage == msg
    assert len(signed.signature) > 0
    assert len(signed.keyId) == 8
    assert len(signed.leadingTwoOctets) == 2


@pytest.mark.parametrize("bits", [1024, 2048])
def test_sign_works_for_both_key_sizes(auth, make_key_pair, bits):
    """One body, run once per allowed key size. pytest reports them separately."""
    priv, pub = make_key_pair(bits=bits)

    signed = auth.sign(b"size check", priv)

    assert auth.verify(signed, pub) is True


def test_leading_two_octets_match_sha1(auth, key_pair):
    priv, _ = key_pair
    msg = b"check the digest prefix"

    signed = auth.sign(msg, priv)

    assert signed.leadingTwoOctets == hashlib.sha1(msg).digest()[:2]


def test_keyid_is_least_significant_64_bits(auth, key_pair):
    priv, pub = key_pair

    signed = auth.sign(b"anything", priv)

    expected = (modulus_of(pub) % (2**64)).to_bytes(8, "big")
    assert signed.keyId == expected


def test_two_signatures_share_same_keyid(auth, key_pair):
    """keyId identifies the key, so it must not depend on the message."""
    priv, _ = key_pair

    a = auth.sign(b"message one", priv)
    b = auth.sign(b"message two", priv)

    assert a.keyId == b.keyId


# ---------------------------------------------------------------------------
# verifying
# ---------------------------------------------------------------------------

def test_verify_accepts_valid_signature(auth, key_pair):
    priv, pub = key_pair

    signed = auth.sign(b"authentic message", priv)

    assert auth.verify(signed, pub) is True


def test_verify_rejects_tampered_message(auth, key_pair):
    priv, pub = key_pair

    signed = auth.sign(b"original content", priv)
    signed.rawMessage = b"tampered content"

    assert auth.verify(signed, pub) is False


def test_verify_rejects_tampered_signature(auth, key_pair):
    priv, pub = key_pair

    signed = auth.sign(b"original content", priv)
    corrupted = bytearray(signed.signature)
    corrupted[0] ^= 0x01
    signed.signature = bytes(corrupted)

    assert auth.verify(signed, pub) is False


def test_verify_rejects_wrong_public_key(auth, make_key_pair):
    priv, _ = make_key_pair()
    _, other_pub = make_key_pair()  # a different pair

    signed = auth.sign(b"signed with key A", priv)

    assert auth.verify(signed, other_pub) is False


# ---------------------------------------------------------------------------
# serialization round trip
# ---------------------------------------------------------------------------

def test_serialization_round_trip_preserves_fields(auth, key_pair):
    priv, _ = key_pair

    original = auth.sign(b"round trip me", priv)
    restored = fromBytesToSignedMessage(toBytesFromSignedMessage(original))

    assert restored.rawMessage == original.rawMessage
    assert restored.signature == original.signature
    assert restored.keyId == original.keyId
    assert restored.leadingTwoOctets == original.leadingTwoOctets
    # packed as whole seconds, so compare at second precision
    assert int(restored.timestamp.timestamp()) == int(original.timestamp.timestamp())


def test_verify_still_works_after_round_trip(auth, key_pair):
    priv, pub = key_pair

    original = auth.sign(b"survive the wire", priv)
    restored = fromBytesToSignedMessage(toBytesFromSignedMessage(original))

    assert auth.verify(restored, pub) is True


def test_timestamp_is_utc_after_round_trip(auth, key_pair):
    priv, _ = key_pair

    original = auth.sign(b"time zone check", priv)
    restored = fromBytesToSignedMessage(toBytesFromSignedMessage(original))

    assert restored.timestamp.tzinfo is not None
    assert restored.timestamp.utcoffset() == timezone.utc.utcoffset(None)


def test_fromBytes_rejects_truncated_data():
    """Header needs 8 bytes; anything shorter must blow up rather than parse
    into garbage. Demonstrates pytest.raises."""
    with pytest.raises(Exception):
        fromBytesToSignedMessage(b"\x00\x01")


# ---------------------------------------------------------------------------
# password-protected key / edge cases
# ---------------------------------------------------------------------------

def test_sign_with_password_protected_key(auth, make_key_pair):
    password = b"s3cret-passphrase"
    priv, pub = make_key_pair(password=password)

    signed = auth.sign(b"locked private key", priv, password=password)

    assert auth.verify(signed, pub) is True


def test_empty_message_can_be_signed_and_verified(auth, key_pair):
    priv, pub = key_pair

    signed = auth.sign(b"", priv)

    assert signed.rawMessage == b""
    assert auth.verify(signed, pub) is True