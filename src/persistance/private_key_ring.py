"""
Private key ring for the PGP scheme.
Holds key pairs that belong to the local
user: one row per pair, with the private key encrypted at rest.
E(H(password), PRkey)(PKCS8 PEM encryption) which already derives its
symmetric key from a password hash.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization


from persistance.user import UserService
from persistance import key_ring_utils as utils
from services.pem_service import PEMService

RING_FILENAME = "private_key_ring.json"


@dataclass
class PrivateKeyRingRow:
    timestamp: datetime
    key_id: bytes
    public_key_pem: bytes
    encrypted_private_key_pem: bytes
    user_email: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "keyId": self.key_id.hex(),
            "publicKeyPem": self.public_key_pem.decode("ascii"),
            "encryptedPrivateKeyPem": self.encrypted_private_key_pem.decode("ascii"),
            "userEmail": self.user_email,
        }

    @staticmethod
    def from_dict(data: dict) -> "PrivateKeyRingRow":
        return PrivateKeyRingRow(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            key_id=bytes.fromhex(data["keyId"]),
            public_key_pem=data["publicKeyPem"].encode("ascii"),
            encrypted_private_key_pem=data["encryptedPrivateKeyPem"].encode("ascii"),
            user_email=data["userEmail"],
        )


class PrivateKeyRing:
    _instance = None

    def __new__(cls, folder_path: str = None):
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._setup(folder_path)
            cls._instance = instance
        return cls._instance

    def _setup(self, folder_path: str) -> None:
        if folder_path is None:
            raise ValueError("Folder Path must be provided")
        self.folderPath = folder_path
        self.filePath = os.path.join(folder_path, RING_FILENAME)

        os.makedirs(folder_path, exist_ok=True)
        if not os.path.exists(self.filePath):
            self._writeRows([])

        self.rows: list[PrivateKeyRingRow] = self._readRows()

    @classmethod
    def resetSingleton(cls) -> None:
        cls._instance = None


    def _readRows(self) -> list[PrivateKeyRingRow]:
        with open(self.filePath, "r", encoding="ascii") as file:
            data = json.load(file)
        return [PrivateKeyRingRow.from_dict(row) for row in data]

    def _writeRows(self, rows: list[PrivateKeyRingRow]) -> None:
        with open(self.filePath, "w", encoding="ascii") as file:
            json.dump([row.to_dict() for row in rows], file, indent=2)


    def findByKeyId(self, keyId: bytes) -> PrivateKeyRingRow | None:
        return next((row for row in self.rows if row.key_id == keyId and row.user_email == UserService().getActiveUser().email), None)

    def _requireOwnRow(self, keyId: bytes) -> PrivateKeyRingRow:
        row = self.findByKeyId(keyId)
        if row is None:
            raise ValueError(f"no private key ring row for keyId {keyId.hex()}")
        return row

    def getAllRows(self) -> list[PrivateKeyRingRow]:
        """All rows owned by active_user."""
        return [row for row in self.rows if row.user_email == UserService().getActiveUser().email]

    def generateKeyPair(self, keySize: int, password: bytes) -> PrivateKeyRingRow:
        privatePem, publicPem = PEMService(key_size=keySize).generateKeyPair()
        return self._storeKeyPair(publicPem, privatePem, password)

    def importKeyPair(self, filePath: str, password: bytes) -> PrivateKeyRingRow:
        privatePem, publicPem = PEMService().importFromFile(filePath)
        if privatePem is None:
            raise ValueError("file does not contain a private key")
        return self._storeKeyPair(publicPem, privatePem, password)

    def _storeKeyPair(self, publicPem: bytes, privatePem: bytes, password: bytes) -> PrivateKeyRingRow:
        keyId = utils.keyIdFromPublicKeyPem(publicPem)
        privateKey = serialization.load_pem_private_key(privatePem, password=None)
        encryptedPrivateKeyPem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        row = PrivateKeyRingRow(
            timestamp=datetime.now(timezone.utc),
            key_id=keyId,
            public_key_pem=publicPem,
            encrypted_private_key_pem=encryptedPrivateKeyPem,
            user_email=UserService().getActiveUser().email,
        )
        self.rows.append(row)
        self._writeRows(self.rows)
        return row

    # -----------------------------------------------------------------
    # delete
    # -----------------------------------------------------------------

    def deleteRow(self, keyId: bytes) -> bool:
        """Delete the row for keyId (must belong to active_user), cascading
        into the public key ring
        """
        row = self._requireOwnRow(keyId)
        self.rows.remove(row)
        self._writeRows(self.rows)

        from persistance.public_key_ring import PublicKeyRing  # deferred: avoids circular import
        # mimics the network broadcast to all peers that a key is deleted so they should invalidate their entries in PubKR
        PublicKeyRing(self.folderPath).deleteAllRowsForKeyId(keyId) 
        return True


    def exportPublicKey(self, keyId: bytes, filePath: str) -> None:
        row = self._requireOwnRow(keyId)
        PEMService().exportToFile(filePath, None, row.public_key_pem)

    def exportKeyPair(self, keyId: bytes, password: bytes, filePath: str) -> None:
        row = self._requireOwnRow(keyId)
        privatePem = self.getDecryptedPrivateKeyPem(keyId, password)
        PEMService().exportToFile(filePath, privatePem, row.public_key_pem)

    def getDecryptedPrivateKeyPem(self, keyId: bytes, password: bytes) -> bytes:
        """Decrypt the row's private key with `password` and re-export it
        unencrypted, ready to hand to AuthenticationService.sign."""
        row = self._requireOwnRow(keyId)
        privateKey = serialization.load_pem_private_key(row.encrypted_private_key_pem, password=password)
        return privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
