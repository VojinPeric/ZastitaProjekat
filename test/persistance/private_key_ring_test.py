"""
pytest tests for PrivateKeyRing.

PEMService's own PEM generation/import/export correctness is covered by
services/pem_service_test.py - here we only rely on it to produce key
material and focus on ring behaviour: read queries, encryption/decryption
at rest, and add/delete.
"""

import json

import pytest
from cryptography.hazmat.primitives import serialization

from persistance import key_ring_utils
from persistance.user import UserService
from persistance.private_key_ring import PrivateKeyRing
from services.pem_service import PEMService

KEY_SIZE = 1024  # small size keeps key generation fast in tests


# ---------------------------------------------------------------------------
# add (generate / import)
# ---------------------------------------------------------------------------

def test_generate_key_pair_stores_a_row_owned_by_active_user(ring_folder, active_user):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"password")

    assert row.user_email == active_user.email
    assert row.key_id == key_ring_utils.keyIdFromPublicKeyPem(row.public_key_pem)
    assert ring.findByKeyId(row.key_id) is row


def test_import_key_pair_stores_the_imported_key(ring_folder, active_user, tmp_path):
    priv, pub = PEMService(key_size=KEY_SIZE).generateKeyPair()
    path = tmp_path / "keypair.pem"
    PEMService().exportToFile(str(path), priv, pub)

    ring = PrivateKeyRing(ring_folder)
    row = ring.importKeyPair(str(path), b"password")

    assert row.public_key_pem == pub
    assert row.user_email == active_user.email


def test_import_public_only_file_is_rejected(ring_folder, active_user, tmp_path):
    _, pub = PEMService(key_size=KEY_SIZE).generateKeyPair()
    path = tmp_path / "public_only.pem"
    PEMService().exportToFile(str(path), None, pub)

    ring = PrivateKeyRing(ring_folder)
    with pytest.raises(ValueError):
        ring.importKeyPair(str(path), b"password")


# ---------------------------------------------------------------------------
# read queries
# ---------------------------------------------------------------------------

def test_get_all_rows_only_returns_active_users_rows(ring_folder, active_user, second_user):
    ring = PrivateKeyRing(ring_folder)
    own_row = ring.generateKeyPair(KEY_SIZE, b"password")

    UserService().login(second_user.username)
    other_row = ring.generateKeyPair(KEY_SIZE, b"password")
    UserService().login(active_user.username)

    assert ring.getAllRows() == [own_row]
    assert other_row not in ring.getAllRows()


def test_get_row_by_key_id_hides_rows_owned_by_other_users(ring_folder, active_user, second_user):
    ring = PrivateKeyRing(ring_folder)
    own_row = ring.generateKeyPair(KEY_SIZE, b"password")

    UserService().login(second_user.username)
    other_row = ring.generateKeyPair(KEY_SIZE, b"password")
    UserService().login(active_user.username)

    assert ring.getRowByKeyId(own_row.key_id) is own_row
    assert ring.getRowByKeyId(other_row.key_id) is None


def test_find_by_key_id_ignores_ownership(ring_folder, active_user, second_user):
    """Unlike getRowByKeyId, findByKeyId is the internal, unrestricted lookup."""
    ring = PrivateKeyRing(ring_folder)

    UserService().login(second_user.username)
    other_row = ring.generateKeyPair(KEY_SIZE, b"password")
    UserService().login(active_user.username)

    assert ring.findByKeyId(other_row.key_id) is other_row


# ---------------------------------------------------------------------------
# encryption / decryption at rest
# ---------------------------------------------------------------------------

def test_stored_private_key_is_encrypted_at_rest(ring_folder, active_user):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"correct horse")

    assert b"ENCRYPTED" in row.encrypted_private_key_pem
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(row.encrypted_private_key_pem, password=None)


def test_decrypted_private_key_matches_generated_key(ring_folder, active_user):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"correct horse")

    decrypted_pem = ring.getDecryptedPrivateKeyPem(row.key_id, b"correct horse")
    decrypted_key = serialization.load_pem_private_key(decrypted_pem, password=None)
    public_key = serialization.load_pem_public_key(row.public_key_pem)

    assert decrypted_key.public_key().public_numbers() == public_key.public_numbers()


def test_wrong_password_fails_to_decrypt(ring_folder, active_user):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"correct horse")

    with pytest.raises(ValueError):
        ring.getDecryptedPrivateKeyPem(row.key_id, b"wrong password")


# ---------------------------------------------------------------------------
# JSON persistence
# ---------------------------------------------------------------------------

def test_row_survives_json_round_trip(ring_folder, active_user):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"password")

    with open(ring.filePath, "r", encoding="ascii") as file:
        data = json.load(file)

    assert len(data) == 1
    assert data[0]["keyId"] == row.key_id.hex()
    assert data[0]["userEmail"] == row.user_email
    assert data[0]["encryptedPrivateKeyPem"].startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")

    PrivateKeyRing.resetSingleton()
    reloaded = PrivateKeyRing(ring_folder)
    reloaded_row = reloaded.findByKeyId(row.key_id)

    assert reloaded_row == row


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

def test_delete_row_removes_it_and_returns_true(ring_folder, active_user):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"password")

    assert ring.deleteRow(row.key_id) is True
    assert ring.findByKeyId(row.key_id) is None


def test_delete_row_missing_key_raises(ring_folder, active_user):
    ring = PrivateKeyRing(ring_folder)
    with pytest.raises(ValueError):
        ring.deleteRow(b"\x00" * 8)


def test_delete_row_rejects_non_owner(ring_folder, active_user, second_user):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"password")

    UserService().login(second_user.username)
    with pytest.raises(PermissionError):
        ring.deleteRow(row.key_id)
    UserService().login(active_user.username)

    assert ring.findByKeyId(row.key_id) is row


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def test_export_public_key_writes_public_pem_only(ring_folder, active_user, tmp_path):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"password")

    out = tmp_path / "pub.pem"
    ring.exportPublicKey(row.key_id, str(out))

    assert out.read_bytes() == row.public_key_pem


def test_export_key_pair_writes_decrypted_private_key(ring_folder, active_user, tmp_path):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"password")

    out = tmp_path / "pair.pem"
    ring.exportKeyPair(row.key_id, b"password", str(out))

    data = out.read_bytes()
    assert b"-----BEGIN PRIVATE KEY-----" in data
    assert row.public_key_pem in data


def test_export_key_pair_rejects_wrong_password(ring_folder, active_user, tmp_path):
    ring = PrivateKeyRing(ring_folder)
    row = ring.generateKeyPair(KEY_SIZE, b"password")

    with pytest.raises(ValueError):
        ring.exportKeyPair(row.key_id, b"wrong password", str(tmp_path / "pair.pem"))
