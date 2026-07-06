"""
pytest tests for PEMService.
"""

import pytest
from cryptography.hazmat.primitives import serialization

from services.pem_service import PEMService, DEFAULT_KEY_SIZE, DEFAULT_PUBLIC_EXPONENT


@pytest.fixture
def service():
    return PEMService(key_size=1024)


# ---------------------------------------------------------------------------
# key generation
# ---------------------------------------------------------------------------

def test_generate_key_pair_produces_valid_pem_blocks(service):
    priv, pub = service.generateKeyPair()

    assert priv.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")
    # round trip through cryptography confirms they're well-formed
    serialization.load_pem_private_key(priv, password=None)
    serialization.load_pem_public_key(pub)


def test_generate_key_pair_public_matches_private(service):
    priv, pub = service.generateKeyPair()

    private_key = serialization.load_pem_private_key(priv, password=None)
    public_key = serialization.load_pem_public_key(pub)

    assert private_key.public_key().public_numbers() == public_key.public_numbers()


def test_generate_key_pair_uses_configured_key_size():
    service = PEMService(key_size=1024)
    priv, _ = service.generateKeyPair()

    private_key = serialization.load_pem_private_key(priv, password=None)
    assert private_key.key_size == 1024


# ---------------------------------------------------------------------------
# export / import round trip
# ---------------------------------------------------------------------------

def test_export_then_import_round_trips_key_pair(service, tmp_path):
    priv, pub = service.generateKeyPair()
    path = tmp_path / "keypair.pem"

    service.exportToFile(str(path), priv, pub)
    restored_priv, restored_pub = service.importFromFile(str(path))

    assert restored_priv is not None
    original_numbers = serialization.load_pem_private_key(priv, password=None).private_numbers()
    restored_numbers = serialization.load_pem_private_key(restored_priv, password=None).private_numbers()
    assert original_numbers == restored_numbers
    assert restored_pub == pub or serialization.load_pem_public_key(
        restored_pub
    ).public_numbers() == serialization.load_pem_public_key(pub).public_numbers()


def test_public_only_file_imports_with_none_private_key(service, tmp_path):
    _, pub = service.generateKeyPair()
    path = tmp_path / "public_only.pem"

    service.exportToFile(str(path), None, pub)
    restored_priv, restored_pub = service.importFromFile(str(path))

    assert restored_priv is None
    assert serialization.load_pem_public_key(restored_pub).public_numbers() == \
        serialization.load_pem_public_key(pub).public_numbers()


def test_exported_key_pair_file_contains_both_blocks(service, tmp_path):
    priv, pub = service.generateKeyPair()
    path = tmp_path / "keypair.pem"

    service.exportToFile(str(path), priv, pub)
    data = path.read_bytes()

    assert b"-----BEGIN PRIVATE KEY-----" in data
    assert b"-----BEGIN PUBLIC KEY-----" in data


# ---------------------------------------------------------------------------
# config / validation
# ---------------------------------------------------------------------------

def test_default_config_is_used():
    service = PEMService()
    assert service.key_size == DEFAULT_KEY_SIZE
    assert service.public_exponent == DEFAULT_PUBLIC_EXPONENT


def test_invalid_key_size_rejected():
    with pytest.raises(ValueError):
        PEMService(key_size=0)
    with pytest.raises(ValueError):
        PEMService(key_size=-5)


def test_invalid_public_exponent_rejected():
    with pytest.raises(ValueError):
        PEMService(key_size=1024, public_exponent=0)
    with pytest.raises(ValueError):
        PEMService(key_size=1024, public_exponent=-1)
