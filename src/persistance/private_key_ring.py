"""
Private key ring for the PGP scheme.

Holds key pairs that belong to (were generated or imported by) the local
user: one row per pair, with the private key encrypted at rest -
E(H(password), PRkey), i.e. PKCS8 PEM encryption, which already derives its
symmetric key from a password hash. Every operation here is only ever
allowed on rows owned by the currently active user (row.userEmail ==
user.active_user.Email); for anything else, look the user up through
user.py (UserRing).
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization

from persistance import user as user_module
from services.pem_service import PEMService

RING_FILENAME = "private_key_ring.json"


def _keyIdFromPublicKeyPem(publicKeyPem: bytes) -> bytes:
    publicKey = serialization.load_pem_public_key(publicKeyPem)
    modulus = publicKey.public_numbers().n
    return (modulus % (2 ** 64)).to_bytes(8, "big")


@dataclass
class PrivateKeyRingRow:
    timestamp: datetime
    keyId: bytes
    publicKeyPem: bytes
    encryptedPrivateKeyPem: bytes
    userEmail: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "keyId": self.keyId.hex(),
            "publicKeyPem": self.publicKeyPem.decode("ascii"),
            "encryptedPrivateKeyPem": self.encryptedPrivateKeyPem.decode("ascii"),
            "userEmail": self.userEmail,
        }

    @staticmethod
    def from_dict(data: dict) -> "PrivateKeyRingRow":
        return PrivateKeyRingRow(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            keyId=bytes.fromhex(data["keyId"]),
            publicKeyPem=data["publicKeyPem"].encode("ascii"),
            encryptedPrivateKeyPem=data["encryptedPrivateKeyPem"].encode("ascii"),
            userEmail=data["userEmail"],
        )


class PrivateKeyRing:
    """
    Singleton wrapping the local private_key_ring.json file. The first call
    to PrivateKeyRing(folder_path) creates (if missing) and loads the ring
    file at <folder_path>/private_key_ring.json; every later call from
    anywhere in the process returns that same instance, regardless of the
    folder_path passed in.
    """

    _instance = None

    def __new__(cls, folder_path: str):
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._setup(folder_path)
            cls._instance = instance
        return cls._instance

    def _setup(self, folder_path: str) -> None:
        self.folderPath = folder_path
        self.filePath = os.path.join(folder_path, RING_FILENAME)

        os.makedirs(folder_path, exist_ok=True)
        if not os.path.exists(self.filePath):
            self._writeRows([])

        self.rows: list[PrivateKeyRingRow] = self._readRows()

    @classmethod
    def resetSingleton(cls) -> None:
        """Test-only escape hatch: forget the cached instance so a fresh
        folder_path can be used to build a new one."""
        cls._instance = None

    # -----------------------------------------------------------------
    # persistence
    # -----------------------------------------------------------------

    def _readRows(self) -> list[PrivateKeyRingRow]:
        with open(self.filePath, "r", encoding="ascii") as file:
            data = json.load(file)
        return [PrivateKeyRingRow.from_dict(row) for row in data]

    def _writeRows(self, rows: list[PrivateKeyRingRow]) -> None:
        with open(self.filePath, "w", encoding="ascii") as file:
            json.dump([row.to_dict() for row in rows], file, indent=2)

    # -----------------------------------------------------------------
    # lookup / authorization
    # -----------------------------------------------------------------

    def findByKeyId(self, keyId: bytes) -> PrivateKeyRingRow | None:
        return next((row for row in self.rows if row.keyId == keyId), None)

    def _requireOwnRow(self, keyId: bytes) -> PrivateKeyRingRow:
        row = self.findByKeyId(keyId)
        if row is None:
            raise ValueError(f"no private key ring row for keyId {keyId.hex()}")
        if row.userEmail != user_module.active_user.Email:
            raise PermissionError("only the row's owner can access it")
        return row

    def getRowByKeyId(self, keyId: bytes) -> PrivateKeyRingRow | None:
        """Read a row, restricted to rows owned by active_user."""
        row = self.findByKeyId(keyId)
        if row is None or row.userEmail != user_module.active_user.Email:
            return None
        return row

    def getAllRows(self) -> list[PrivateKeyRingRow]:
        """All rows owned by active_user."""
        return [row for row in self.rows if row.userEmail == user_module.active_user.Email]

    # -----------------------------------------------------------------
    # add (generate or import)
    # -----------------------------------------------------------------

    def generateKeyPair(self, keySize: int, password: bytes) -> PrivateKeyRingRow:
        """Generate a fresh key pair of size `keySize` and store it, private
        key encrypted at rest with `password`."""
        privatePem, publicPem = PEMService(key_size=keySize).generateKeyPair()
        return self._storeKeyPair(publicPem, privatePem, password)

    def importKeyPair(self, filePath: str, password: bytes) -> PrivateKeyRingRow:
        """Import a key pair from an (unencrypted) PEM file at `filePath`
        and store it, private key encrypted at rest with `password`."""
        privatePem, publicPem = PEMService().importFromFile(filePath)
        if privatePem is None:
            raise ValueError("file does not contain a private key")
        return self._storeKeyPair(publicPem, privatePem, password)

    def _storeKeyPair(self, publicPem: bytes, privatePem: bytes, password: bytes) -> PrivateKeyRingRow:
        keyId = _keyIdFromPublicKeyPem(publicPem)
        privateKey = serialization.load_pem_private_key(privatePem, password=None)
        encryptedPrivateKeyPem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        row = PrivateKeyRingRow(
            timestamp=datetime.now(timezone.utc),
            keyId=keyId,
            publicKeyPem=publicPem,
            encryptedPrivateKeyPem=encryptedPrivateKeyPem,
            userEmail=user_module.active_user.Email,
        )
        self.rows.append(row)
        self._writeRows(self.rows)
        return row

    # -----------------------------------------------------------------
    # delete
    # -----------------------------------------------------------------

    def deleteRow(self, keyId: bytes) -> bool:
        """Delete the row for keyId (must belong to active_user), cascading
        into the public key ring: every row there for this same keyId is
        also removed."""
        row = self._requireOwnRow(keyId)
        self.rows.remove(row)
        self._writeRows(self.rows)

        from persistance.public_key_ring import PublicKeyRing  # deferred: avoids circular import
        PublicKeyRing(self.folderPath).deleteAllRowsForKeyId(keyId)
        return True

    # -----------------------------------------------------------------
    # export
    # -----------------------------------------------------------------

    def exportPublicKey(self, keyId: bytes, filePath: str) -> None:
        row = self._requireOwnRow(keyId)
        PEMService().exportToFile(filePath, None, row.publicKeyPem)

    def exportKeyPair(self, keyId: bytes, password: bytes, filePath: str) -> None:
        """Export the full key pair, decrypting the private key with
        `password` first (also serves as the password check)."""
        row = self._requireOwnRow(keyId)
        privatePem = self.getDecryptedPrivateKeyPem(keyId, password)
        PEMService().exportToFile(filePath, privatePem, row.publicKeyPem)

    def getDecryptedPrivateKeyPem(self, keyId: bytes, password: bytes) -> bytes:
        """Decrypt the row's private key with `password` and re-export it
        unencrypted, ready to hand to AuthenticationService.sign."""
        row = self._requireOwnRow(keyId)
        privateKey = serialization.load_pem_private_key(row.encryptedPrivateKeyPem, password=password)
        return privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
