"""
Integration tests spanning UserRing, PrivateKeyRing and PublicKeyRing
together - multi-user web-of-trust scenarios and cross-ring cascades that
don't belong in a single ring's own test file.
"""

import pytest

from persistance import user as user_module
from persistance.user import UserRing
from persistance.private_key_ring import PrivateKeyRing
from persistance.public_key_ring import PublicKeyRing, FULL_TRUST_THRESHOLD
from services.pem_service import PEMService

KEY_SIZE = 1024


def _export_public_only(tmp_path, publicKeyPem, name):
    path = tmp_path / name
    PEMService().exportToFile(str(path), None, publicKeyPem)
    return str(path)


def test_key_legitimacy_reaches_full_trust_after_two_full_trust_signatures(ring_folder, tmp_path):
    user_ring = UserRing(ring_folder)
    alice = user_ring.addUser("alice", "alice@example.com", ring_folder)
    carol = user_ring.addUser("carol", "carol@example.com", ring_folder)
    dave = user_ring.addUser("dave", "dave@example.com", ring_folder)

    private_ring = PrivateKeyRing(ring_folder)
    public_ring = PublicKeyRing(ring_folder)

    user_module.active_user = carol
    carol_row = private_ring.generateKeyPair(KEY_SIZE, b"carol-pw")

    user_module.active_user = dave
    dave_row = private_ring.generateKeyPair(KEY_SIZE, b"dave-pw")

    # alice adds bob's (unrelated, remote) public key as the row to certify,
    # and separately vouches for carol's and dave's real keys with full trust
    user_module.active_user = alice
    bob_pub_path = _export_public_only(tmp_path, PEMService(key_size=KEY_SIZE).generateKeyPair()[1], "bob_pub.pem")
    target_row = public_ring.addRow(bob_pub_path, KEY_SIZE, "bob@example.com", ownerTrust=0)

    carol_pub_path = _export_public_only(tmp_path, carol_row.public_key_pem, "carol_pub.pem")
    public_ring.addRow(carol_pub_path, KEY_SIZE, carol.email, ownerTrust=FULL_TRUST_THRESHOLD)

    dave_pub_path = _export_public_only(tmp_path, dave_row.public_key_pem, "dave_pub.pem")
    public_ring.addRow(dave_pub_path, KEY_SIZE, dave.email, ownerTrust=FULL_TRUST_THRESHOLD)

    # a single full-trust signature isn't enough to cross the legitimacy threshold
    user_module.active_user = carol
    public_ring.signRow(target_row.key_id, carol_row.key_id, b"carol-pw")
    assert target_row.key_legitimacy == 0

    # a second full-trust signature pushes the weighted sum over the threshold
    user_module.active_user = dave
    public_ring.signRow(target_row.key_id, dave_row.key_id, b"dave-pw")

    assert target_row.key_legitimacy == 1
    assert len(target_row.signatures) == 2


def test_sign_row_requires_the_exact_key_vouched_for(ring_folder, tmp_path):
    user_ring = UserRing(ring_folder)
    alice = user_ring.addUser("alice", "alice@example.com", ring_folder)
    carol = user_ring.addUser("carol", "carol@example.com", ring_folder)

    private_ring = PrivateKeyRing(ring_folder)
    public_ring = PublicKeyRing(ring_folder)

    user_module.active_user = carol
    vouched_for_row = private_ring.generateKeyPair(KEY_SIZE, b"carol-pw")
    unrelated_row = private_ring.generateKeyPair(KEY_SIZE, b"carol-pw-2")

    user_module.active_user = alice
    bob_pub_path = _export_public_only(tmp_path, PEMService(key_size=KEY_SIZE).generateKeyPair()[1], "bob_pub.pem")
    target_row = public_ring.addRow(bob_pub_path, KEY_SIZE, "bob@example.com", ownerTrust=0)

    # alice only vouches for carol's `vouched_for_row` key, not `unrelated_row`
    carol_pub_path = _export_public_only(tmp_path, vouched_for_row.public_key_pem, "carol_pub.pem")
    public_ring.addRow(carol_pub_path, KEY_SIZE, carol.email, ownerTrust=90)

    user_module.active_user = carol
    with pytest.raises(PermissionError):
        public_ring.signRow(target_row.key_id, unrelated_row.key_id, b"carol-pw-2")

    # the actual vouched-for key is permitted
    public_ring.signRow(target_row.key_id, vouched_for_row.key_id, b"carol-pw")
    assert len(target_row.signatures) == 1


def test_deleting_a_private_key_cascades_and_strips_dependent_signatures(ring_folder, tmp_path):
    user_ring = UserRing(ring_folder)
    alice = user_ring.addUser("alice", "alice@example.com", ring_folder)
    bob = user_ring.addUser("bob", "bob@example.com", ring_folder)

    private_ring = PrivateKeyRing(ring_folder)
    public_ring = PublicKeyRing(ring_folder)

    user_module.active_user = bob
    bob_row = private_ring.generateKeyPair(KEY_SIZE, b"bob-pw")

    user_module.active_user = alice
    alice_row = private_ring.generateKeyPair(KEY_SIZE, b"alice-pw")
    bob_pub_path = _export_public_only(tmp_path, bob_row.public_key_pem, "bob_pub.pem")
    target_row = public_ring.addRow(bob_pub_path, KEY_SIZE, bob.email, ownerTrust=50)

    public_ring.signRow(target_row.key_id, alice_row.key_id, b"alice-pw")
    assert len(target_row.signatures) == 1

    # alice deletes her own signing key: it should disappear from the
    # private ring, and every signature she made should be stripped from
    # the public ring even though she never touched public_ring directly
    private_ring.deleteRow(alice_row.key_id)

    assert private_ring.findByKeyId(alice_row.key_id) is None
    remaining_row = public_ring._findRowByKeyId(target_row.key_id)
    assert remaining_row.signatures == []
