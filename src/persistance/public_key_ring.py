"""
Public key ring for the PGP scheme.

The ring is one JSON table: each row is a public key someone has added,
plus the owner-trust needed to decide how much to
trust certificates that chain through other people's signatures. It is a
singleton because the process only ever works against a single ring file
at a time - we can read anyone's public key to check signatures, but only
the locally logged-in user (`user.active_user`) can add/remove/sign rows.

Row terminology (matches the original spec):
    row.userEmail  -> email of the User who added this row (the "owner of the row").
    row.ownerEmail -> email of the User the key in this row actually belongs to.
Look up a User's other details (username, message box) through user.py
(UserRing) if needed - rows here only keep the email.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization

from persistance import user as user_module
from services.pem_service import PEMService
from persistance.private_key_ring import PrivateKeyRing
from services.authentication_service import AuthenticationService

RING_FILENAME = "public_key_ring.json"

# signature trust weights (percent of ownerTrust) -> weight used by keyLegitimacy
FULL_TRUST_THRESHOLD = 75
FULL_TRUST_WEIGHT = 1
MARGINAL_TRUST_WEIGHT = 1 / 3
LEGITIMACY_THRESHOLD = 1


@dataclass
class Signature:
    """One certification signature attached to a ring row."""
    IDPU_signature: bytes  # keyId of the signer
    PU_signature: bytes    # signer's public key PEM, embedded for self-contained verification
    IDPU_signed: bytes     # keyId of the row being signed
    Signature: bytes       # E(PR_signature: H(IDPU_signature, PU_signature, IDPU_signed))
    trust: int             # the corresponding Signature Trust (see PublicKeyRing.signRow)

    def to_dict(self) -> dict:
        return {
            "IDPU_signature": self.IDPU_signature.hex(),
            "PU_signature": self.PU_signature.decode("ascii"),
            "IDPU_signed": self.IDPU_signed.hex(),
            "Signature": self.Signature.hex(),
            "trust": self.trust,
        }

    @staticmethod
    def from_dict(data: dict) -> "Signature":
        return Signature(
            IDPU_signature=bytes.fromhex(data["IDPU_signature"]),
            PU_signature=data["PU_signature"].encode("ascii"),
            IDPU_signed=bytes.fromhex(data["IDPU_signed"]),
            Signature=bytes.fromhex(data["Signature"]),
            trust=data["trust"],
        )


@dataclass
class PublicKeyRingRow:
    timestamp: datetime
    keyId: bytes
    publicKeyPem: bytes
    userEmail: str
    ownerEmail: str
    ownerTrust: int
    keyLegitimacy: int
    signatures: list = field(default_factory=list)  # list[Signature]

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "keyId": self.keyId.hex(),
            "publicKeyPem": self.publicKeyPem.decode("ascii"),
            "userEmail": self.userEmail,
            "ownerEmail": self.ownerEmail,
            "ownerTrust": self.ownerTrust,
            "keyLegitimacy": self.keyLegitimacy,
            "signatures": [s.to_dict() for s in self.signatures],
        }

    @staticmethod
    def from_dict(data: dict) -> "PublicKeyRingRow":
        return PublicKeyRingRow(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            keyId=bytes.fromhex(data["keyId"]),
            publicKeyPem=data["publicKeyPem"].encode("ascii"),
            userEmail=data["userEmail"],
            ownerEmail=data["ownerEmail"],
            ownerTrust=data["ownerTrust"],
            keyLegitimacy=data["keyLegitimacy"],
            signatures=[Signature.from_dict(s) for s in data.get("signatures", [])],
        )


class PublicKeyRing:
    """
    Singleton wrapping the local public key ring JSON file. The first call
    to PublicKeyRing(folder_path) creates (if missing) and loads the ring
    file at <folder_path>/public_key_ring.json; every later call from
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
        self._authService = AuthenticationService()
        self.folderPath = folder_path
        self.filePath = os.path.join(folder_path, RING_FILENAME)

        os.makedirs(folder_path, exist_ok=True)
        if not os.path.exists(self.filePath):
            self._writeRows([])

        self.rows: list[PublicKeyRingRow] = self._readRows()

    @classmethod
    def resetSingleton(cls) -> None:
        """Test-only escape hatch: forget the cached instance so a fresh
        folder_path can be used to build a new one."""
        cls._instance = None

    # -----------------------------------------------------------------
    # persistence
    # -----------------------------------------------------------------

    def _readRows(self) -> list[PublicKeyRingRow]:
        with open(self.filePath, "r", encoding="ascii") as file:
            data = json.load(file)
        return [PublicKeyRingRow.from_dict(row) for row in data]

    def _writeRows(self, rows: list[PublicKeyRingRow]) -> None:
        with open(self.filePath, "w", encoding="ascii") as file:
            json.dump([row.to_dict() for row in rows], file, indent=2)

    # -----------------------------------------------------------------
    # row lookup
    # -----------------------------------------------------------------

    def _findRowByKeyId(self, keyId: bytes) -> PublicKeyRingRow | None:
        return next((row for row in self.rows if row.keyId == keyId), None)

    def getRowByKeyId(self, keyId: bytes) -> PublicKeyRingRow | None:
        """Public read: only returns a row belonging to active_user's own
        ring perspective (row.userEmail == active_user.Email). Signing
        bypasses this, since active_user is allowed to sign rows added by
        other people."""
        row = self._findRowByKeyId(keyId)
        if row is None or row.userEmail != user_module.active_user.Email:
            return None
        return row

    def getAllRows(self) -> list[PublicKeyRingRow]:
        """All rows added by active_user (row.userEmail == active_user.Email)."""
        return [row for row in self.rows if row.userEmail == user_module.active_user.Email]

    # -----------------------------------------------------------------
    # add / delete
    # -----------------------------------------------------------------

    def addRow(self, publicKeyPath: str, keySize: int, ownerEmail: str, ownerTrust: int) -> PublicKeyRingRow:
        """Add a row for the public key imported from publicKeyPath. Only
        usable for remote keys: ownerEmail must not be active_user's own."""
        if ownerEmail == user_module.active_user.Email:
            raise PermissionError("cannot add your own key to the public key ring")

        pemService = PEMService(key_size=keySize)
        _, publicKeyPem = pemService.importFromFile(publicKeyPath)

        publicKey = serialization.load_pem_public_key(publicKeyPem)
        if publicKey.key_size != keySize:
            raise ValueError(f"imported key size {publicKey.key_size} does not match expected {keySize}")

        keyId = self._keyIdFromPublicKeyPem(publicKeyPem)

        row = PublicKeyRingRow(
            timestamp=datetime.now(timezone.utc),
            keyId=keyId,
            publicKeyPem=publicKeyPem,
            userEmail=user_module.active_user.Email,
            ownerEmail=ownerEmail,
            ownerTrust=ownerTrust,
            keyLegitimacy=0,
            signatures=[],
        )

        self.rows.append(row)
        self._writeRows(self.rows)
        return row

    def deleteRow(self, keyId: bytes) -> bool:
        """Delete the row for keyId, only if active_user is its owner (the
        one who added it). Also strips every signature made by that key
        from every other row, and recalculates their keyLegitimacy."""
        row = self._findRowByKeyId(keyId)
        if row is None:
            return False
        if row.userEmail != user_module.active_user.Email:
            raise PermissionError("only the row's owner can delete it")

        self.rows.remove(row)
        self._stripSignaturesByKeyId(keyId)
        self._writeRows(self.rows)
        return True

    def deleteAllRowsForKeyId(self, keyId: bytes) -> None:
        """Used when the underlying private key itself is deleted: remove
        every row for this key regardless of who added it, and strip every
        signature made by this key from the remaining rows."""
        self.rows = [row for row in self.rows if row.keyId != keyId]
        self._stripSignaturesByKeyId(keyId)
        self._writeRows(self.rows)

    def _stripSignaturesByKeyId(self, signerKeyId: bytes) -> None:
        for row in self.rows:
            before = len(row.signatures)
            row.signatures = [sig for sig in row.signatures if sig.IDPU_signature != signerKeyId]
            if len(row.signatures) != before:
                self._recalculateKeyLegitimacy(row)

    # -----------------------------------------------------------------
    # signing
    # -----------------------------------------------------------------

    def signRow(self, rowKeyId: bytes, signerKeyId: bytes, password: bytes) -> Signature:
        """active_user signs the row identified by rowKeyId, using the key
        pair signerKeyId (must be active_user's own, found via the private
        key ring and decrypted with `password`)."""
        row = self._findRowByKeyId(rowKeyId)
        if row is None:
            raise ValueError(f"no public key ring row for keyId {rowKeyId.hex()}")

        if not self._canSign(row):
            raise PermissionError(
                "active_user must own this row, or must have already added "
                "this key owner's key under their own ring"
            )

        privateKeyRing = PrivateKeyRing(self.folderPath)
        privateRow = privateKeyRing.findByKeyId(signerKeyId)
        if privateRow is None:
            raise ValueError(f"no private key ring entry for keyId {signerKeyId.hex()}")
        if privateRow.userEmail != user_module.active_user.Email:
            raise PermissionError("can only sign with your own key pair")

        if any(sig.IDPU_signature == signerKeyId for sig in row.signatures):
            raise ValueError("this key has already signed this row")

        privateKeyPem = privateKeyRing.getDecryptedPrivateKeyPem(signerKeyId, password)

        IDPU_signature = signerKeyId
        PU_signature = privateRow.publicKeyPem
        IDPU_signed = row.keyId
        signedMessage = self._authService.sign(
            IDPU_signature + PU_signature + IDPU_signed, privateKeyPem
        )

        signature = Signature(
            IDPU_signature=IDPU_signature,
            PU_signature=PU_signature,
            IDPU_signed=IDPU_signed,
            Signature=signedMessage.signature,
            trust=self._signatureTrustFor(row, signerKeyId),
        )

        row.signatures.append(signature)
        self._recalculateKeyLegitimacy(row)
        self._writeRows(self.rows)
        return signature

    def _canSign(self, row: PublicKeyRingRow) -> bool:
        activeUserEmail = user_module.active_user.Email
        if row.userEmail == activeUserEmail:
            return True
        return any(
            other.ownerEmail == row.ownerEmail and other.userEmail == activeUserEmail
            for other in self.rows
        )

    def _signatureTrustFor(self, row: PublicKeyRingRow, signerKeyId: bytes) -> int:
        """The Owner Trust that row.userEmail themselves recorded for the
        signer's key elsewhere in the ring (0 if they never added it)."""
        signerRow = next(
            (r for r in self.rows if r.userEmail == row.userEmail and r.keyId == signerKeyId),
            None,
        )
        return signerRow.ownerTrust if signerRow is not None else 0

    # -----------------------------------------------------------------
    # key legitimacy
    # -----------------------------------------------------------------

    def _recalculateKeyLegitimacy(self, row: PublicKeyRingRow) -> None:
        if row.userEmail == user_module.active_user.Email:
            row.keyLegitimacy = 1
            return

        weightSum = sum(
            FULL_TRUST_WEIGHT if sig.trust >= FULL_TRUST_THRESHOLD else MARGINAL_TRUST_WEIGHT
            for sig in row.signatures
        )
        row.keyLegitimacy = 1 if weightSum > LEGITIMACY_THRESHOLD else 0

    @staticmethod
    def _keyIdFromPublicKeyPem(publicKeyPem: bytes) -> bytes:
        publicKey = serialization.load_pem_public_key(publicKeyPem)
        modulus = publicKey.public_numbers().n
        return (modulus % (2 ** 64)).to_bytes(8, "big")
