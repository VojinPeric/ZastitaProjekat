"""
pytest tests for PublicKeyRing.

Only exercises signing between the active user's own rows (a self-added
row, signed with the active user's own key) - scenarios that need real
multi-user web-of-trust setups (several users vouching for each other
across both rings) live in integration_ring_test.py instead.
"""

import json

import pytest
from cryptography.hazmat.primitives import hashes

from persistance import key_ring_utils
from persistance import user as user_module
from persistance.private_key_ring import PrivateKeyRing
from persistance.public_key_ring import PublicKeyRing
from services.authentication_service import AuthenticationService
from services.pem_service import PEMService
from pgp_messages import SignedMessage

KEY_SIZE = 1024
OWNER_EMAIL = "bob@example.com"


def _export_public_only(tmp_path, name="owner_pub.pem"):
    _, pub = PEMService(key_size=KEY_SIZE).generateKeyPair()
    path = tmp_path / name
    PEMService().exportToFile(str(path), None, pub)
    return str(path), pub


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------

def test_add_row_stores_key_owned_by_someone_else(ring_folder, active_user, tmp_path):
    path, pub = _export_public_only(tmp_path)
    ring = PublicKeyRing(ring_folder)

    row = ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)

    assert row.owner_email == OWNER_EMAIL
    assert row.user_email == active_user.email
    assert row.key_id == key_ring_utils.keyIdFromPublicKeyPem(pub)
    assert row.key_legitimacy == 0
    assert row.signatures == []


def test_add_row_rejects_own_key(ring_folder, active_user, tmp_path):
    path, _ = _export_public_only(tmp_path)
    ring = PublicKeyRing(ring_folder)

    with pytest.raises(PermissionError):
        ring.addRow(path, KEY_SIZE, active_user.email, ownerTrust=50)


def test_add_row_rejects_key_size_mismatch(ring_folder, active_user, tmp_path):
    path, _ = _export_public_only(tmp_path)
    ring = PublicKeyRing(ring_folder)

    with pytest.raises(ValueError):
        ring.addRow(path, KEY_SIZE * 2, OWNER_EMAIL, ownerTrust=50)


# ---------------------------------------------------------------------------
# read queries
# ---------------------------------------------------------------------------

def test_get_all_rows_and_get_row_by_key_id_are_scoped_to_active_user(
    ring_folder, active_user, second_user, tmp_path
):
    path, _ = _export_public_only(tmp_path, "own_owner_pub.pem")
    ring = PublicKeyRing(ring_folder)
    own_row = ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)

    user_module.active_user = second_user
    path2, _ = _export_public_only(tmp_path, "other_owner_pub.pem")
    other_row = ring.addRow(path2, KEY_SIZE, "carol@example.com", ownerTrust=10)
    user_module.active_user = active_user

    assert ring.getAllRows() == [own_row]
    assert ring.getRowByKeyId(own_row.key_id) is own_row
    assert ring.getRowByKeyId(other_row.key_id) is None


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

def test_delete_row_missing_returns_false(ring_folder, active_user):
    ring = PublicKeyRing(ring_folder)
    assert ring.deleteRow(b"\x00" * 8) is False


def test_delete_row_rejects_non_owner(ring_folder, active_user, second_user, tmp_path):
    path, _ = _export_public_only(tmp_path)
    ring = PublicKeyRing(ring_folder)
    row = ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)

    user_module.active_user = second_user
    with pytest.raises(PermissionError):
        ring.deleteRow(row.key_id)
    user_module.active_user = active_user

    assert ring.deleteRow(row.key_id) is True
    assert ring._findRowByKeyId(row.key_id) is None


# ---------------------------------------------------------------------------
# signing - correctness of the produced Signature
# ---------------------------------------------------------------------------

def _verify_signature(signature, tampered_payload=None):
    payload = tampered_payload if tampered_payload is not None else (
        signature.idpu_signature + signature.pu_signature + signature.idpu_signed
    )
    digest = hashes.Hash(hashes.SHA1())
    digest.update(payload)

    message = SignedMessage()
    message.rawMessage = payload
    message.signature = signature.signature
    message.leadingTwoOctets = digest.finalize()[:2]

    return AuthenticationService().verify(message, signature.pu_signature)


def test_sign_row_produces_a_verifiable_signature(ring_folder, active_user, tmp_path):
    private_ring = PrivateKeyRing(ring_folder)
    signer_row = private_ring.generateKeyPair(KEY_SIZE, b"password")

    path, _ = _export_public_only(tmp_path)
    public_ring = PublicKeyRing(ring_folder)
    target_row = public_ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)

    signature = public_ring.signRow(target_row.key_id, signer_row.key_id, b"password")

    assert signature.idpu_signature == signer_row.key_id
    assert signature.idpu_signed == target_row.key_id
    assert signature.pu_signature == signer_row.public_key_pem
    assert _verify_signature(signature) is True


def test_tampered_signature_payload_fails_verification(ring_folder, active_user, tmp_path):
    private_ring = PrivateKeyRing(ring_folder)
    signer_row = private_ring.generateKeyPair(KEY_SIZE, b"password")

    path, _ = _export_public_only(tmp_path)
    public_ring = PublicKeyRing(ring_folder)
    target_row = public_ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)

    signature = public_ring.signRow(target_row.key_id, signer_row.key_id, b"password")
    tampered = signature.idpu_signature + signature.pu_signature + b"\x00" + signature.idpu_signed

    assert _verify_signature(signature, tampered_payload=tampered) is False


def test_sign_row_recalculates_key_legitimacy_for_own_rows(ring_folder, active_user, tmp_path):
    private_ring = PrivateKeyRing(ring_folder)
    signer_row = private_ring.generateKeyPair(KEY_SIZE, b"password")

    path, _ = _export_public_only(tmp_path)
    public_ring = PublicKeyRing(ring_folder)
    target_row = public_ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)
    assert target_row.key_legitimacy == 0

    public_ring.signRow(target_row.key_id, signer_row.key_id, b"password")

    assert target_row.key_legitimacy == 1
    assert len(target_row.signatures) == 1


def test_sign_row_rejects_double_signature_from_same_key(ring_folder, active_user, tmp_path):
    private_ring = PrivateKeyRing(ring_folder)
    signer_row = private_ring.generateKeyPair(KEY_SIZE, b"password")

    path, _ = _export_public_only(tmp_path)
    public_ring = PublicKeyRing(ring_folder)
    target_row = public_ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)

    public_ring.signRow(target_row.key_id, signer_row.key_id, b"password")
    with pytest.raises(ValueError):
        public_ring.signRow(target_row.key_id, signer_row.key_id, b"password")


def test_sign_row_rejects_unpermitted_signer(ring_folder, active_user, second_user, tmp_path):
    private_ring = PrivateKeyRing(ring_folder)
    signer_row = private_ring.generateKeyPair(KEY_SIZE, b"password")

    path, _ = _export_public_only(tmp_path)
    public_ring = PublicKeyRing(ring_folder)
    target_row = public_ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)  # added by active_user (alice)

    user_module.active_user = second_user  # bob has no relation to this row or signer_row
    with pytest.raises(PermissionError):
        public_ring.signRow(target_row.key_id, signer_row.key_id, b"password")
    user_module.active_user = active_user


# ---------------------------------------------------------------------------
# JSON persistence
# ---------------------------------------------------------------------------

def test_row_with_signature_round_trips_through_json(ring_folder, active_user, tmp_path):
    private_ring = PrivateKeyRing(ring_folder)
    signer_row = private_ring.generateKeyPair(KEY_SIZE, b"password")

    path, _ = _export_public_only(tmp_path)
    public_ring = PublicKeyRing(ring_folder)
    target_row = public_ring.addRow(path, KEY_SIZE, OWNER_EMAIL, ownerTrust=50)
    public_ring.signRow(target_row.key_id, signer_row.key_id, b"password")

    with open(public_ring.filePath, "r", encoding="ascii") as file:
        data = json.load(file)

    assert len(data) == 1
    assert data[0]["keyId"] == target_row.key_id.hex()
    assert len(data[0]["signatures"]) == 1
    assert data[0]["signatures"][0]["IDPU_signature"] == signer_row.key_id.hex()

    PublicKeyRing.resetSingleton()
    reloaded = PublicKeyRing(ring_folder)
    reloaded_row = reloaded._findRowByKeyId(target_row.key_id)

    assert reloaded_row == target_row
