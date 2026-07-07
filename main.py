"""
Manual end-to-end smoke test: alice signs + encrypts a message to bob, then
bob logs in and receives it (decrypts with his private key + verifies alice's
signature).

Run with src on the path, e.g.:  PYTHONPATH=src python main.py

Note: the key rings are global and file-backed, so re-running this appends new
key pairs to users/KEY_RINGS/*.json. Delete that folder for a clean slate.
"""

import os

from persistance.private_key_ring import PrivateKeyRing
from persistance.public_key_ring import PublicKeyRing
from persistance.user import UserService, UserRing
from services.pem_service import PEMService
from services.pgp_service import PgpService, PgpStep, ROOT_PATH, KEY_RING_DIRNAME


def ensure_user(user_ring, username, email):
    """Register a user only if they're not already in users.json, so the script
    can be re-run without addUser complaining about duplicates."""
    if user_ring.findByUsername(username) is None:
        user_ring.addUser(username, email, username)


# --- register the two users ---
user_ring = UserRing("user_ring")
ensure_user(user_ring, "alice", "alice@example.com")
ensure_user(user_ring, "bob", "bob@example.com")

user_service = UserService()
pem = PEMService()

# the shared key rings (same folder PgpService uses, so the singletons line up)
key_rings_folder = os.path.join(ROOT_PATH, KEY_RING_DIRNAME)
private_ring = PrivateKeyRing(key_rings_folder)
public_ring = PublicKeyRing(key_rings_folder)

# --- bob: generate his own key pair (private key stays in the shared ring,
#     owned by bob), and export the public half so alice can import it ---
user_service.login("bob")
bob_key = private_ring.generateKeyPair(keySize=2048, password=b"bob-pw")
pem.exportToFile("bob_public.pem", None, bob_key.public_key_pem)

# --- alice: her own signing key, import bob's public key, then send to bob ---
user_service.login("alice")
alice_key = private_ring.generateKeyPair(keySize=2048, password=b"alice-pw")
bob_row = public_ring.addRow("bob_public.pem", 2048, "bob@example.com", ownerTrust=1)

alice_pgp = PgpService(PgpStep.ALL)
alice_pgp.send(
    "Cao brate",
    "poruka.pgp",
    filename="poruka",
    signer_key_id=alice_key.key_id,
    signer_password=b"alice-pw",
    recipient_key_id=bob_row.key_id,
)
print("alice sent poruka.pgp")

# --- bob: receive (decrypt with his private key + verify alice's signature) ---
user_service.login("bob")
bob_pgp = PgpService(PgpStep.ALL)
result = bob_pgp.receive("poruka.pgp", password=b"bob-pw")

print("message         :", result.message.msg)
print("applied steps   :", result.applied_steps)
print("signature valid :", result.signature_valid)
print("signer email    :", result.signer_email)
