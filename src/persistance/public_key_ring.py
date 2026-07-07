"""
Public key ring for the PGP scheme.

The ring is one JSON table: each row is a public key someone has added,
plus the owner-trust needed to decide how much to
trust certificates that chain through other people's signatures. It is a
singleton because the process only ever works against a single ring file
at a time - we can read anyone's public key to check signatures, but only
the locally logged-in user (`UserService().getActiveUser()`) can add/remove/sign rows.

Row terminology (matches the original spec):
    row.user_email  -> email of the User who added this row (the "owner of the row").
    row.owner_email -> email of the User the key in this row actually belongs to.
Look up a User's other details (username, message box) through user.py
(UserRing) if needed - rows here only keep the email.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization

from persistance.user import UserService
from persistance import key_ring_utils as utils
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
    idpu_signature: bytes  # keyId of the signer
    pu_signature: bytes    # signer's public key PEM, embedded for self-contained verification
    idpu_signed: bytes     # keyId of the row being signed
    signature: bytes       # E(PR_signature: H(IDPU_signature, PU_signature, IDPU_signed))
    trust: int             # the corresponding Signature Trust (see PublicKeyRing.signRow)

    def to_dict(self) -> dict:
        return {
            "IDPU_signature": self.idpu_signature.hex(),
            "PU_signature": self.pu_signature.decode("ascii"),
            "IDPU_signed": self.idpu_signed.hex(),
            "Signature": self.signature.hex(),
            "Trust": self.trust,
        }

    @staticmethod
    def from_dict(data: dict) -> "Signature":
        return Signature(
            idpu_signature=bytes.fromhex(data["IDPU_signature"]),
            pu_signature=data["PU_signature"].encode("ascii"),
            idpu_signed=bytes.fromhex(data["IDPU_signed"]),
            signature=bytes.fromhex(data["Signature"]),
            trust=data["Trust"],
        )


@dataclass
class PublicKeyRingRow:
    timestamp: datetime
    key_id: bytes
    public_key_pem: bytes
    user_email: str
    owner_email: str
    owner_trust: int
    key_legitimacy: int
    signatures: list = field(default_factory=list)  # list[Signature]

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "keyId": self.key_id.hex(),
            "publicKeyPem": self.public_key_pem.decode("ascii"),
            "userEmail": self.user_email,
            "ownerEmail": self.owner_email,
            "ownerTrust": self.owner_trust,
            "keyLegitimacy": self.key_legitimacy,
            "signatures": [s.to_dict() for s in self.signatures],
        }

    @staticmethod
    def from_dict(data: dict) -> "PublicKeyRingRow":
        return PublicKeyRingRow(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            key_id=bytes.fromhex(data["keyId"]),
            public_key_pem=data["publicKeyPem"].encode("ascii"),
            user_email=data["userEmail"],
            owner_email=data["ownerEmail"],
            owner_trust=data["ownerTrust"],
            key_legitimacy=data["keyLegitimacy"],
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

    def __new__(cls, folder_path: str = None):
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._setup(folder_path)
            cls._instance = instance
        return cls._instance

    def _setup(self, folder_path: str) -> None:
        if folder_path is None:
            raise ValueError("Folder Path must be provided")
        self._authService = AuthenticationService()
        self.folderPath = folder_path
        self.filePath = os.path.join(folder_path, RING_FILENAME)

        os.makedirs(folder_path, exist_ok=True)
        if not os.path.exists(self.filePath):
            self._writeRows([])

        self.rows: list[PublicKeyRingRow] = self._readRows()

    @classmethod
    def resetSingleton(cls) -> None:
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
    # read
    # -----------------------------------------------------------------

    def _findRowByKeyId(self, keyId: bytes, email: str) -> PublicKeyRingRow | None:
        return next((row for row in self.rows if row.key_id == keyId and row.user_email == email), None)

    def getRowByKeyId(self, keyId: bytes) -> PublicKeyRingRow | None:
        """Public read: only returns a row belonging to active_user's own
        ring perspective (row.user_email == active_user.email). Signing
        bypasses this, since active_user is allowed to sign rows added by
        other people."""
        row = self._findRowByKeyId(keyId, UserService().getActiveUser().email)
        if row is None:
            return None
        return row

    def getAllRows(self) -> list[PublicKeyRingRow]:
        """All rows added by active_user (row.user_email == active_user.email)."""
        return [row for row in self.rows if row.user_email == UserService().getActiveUser().email]

    # -----------------------------------------------------------------
    # add
    # -----------------------------------------------------------------

    def addRow(self, publicKeyPath: str, keySize: int, ownerEmail: str, ownerTrust: int) -> PublicKeyRingRow:
        """Add a row for the public key imported from publicKeyPath. Only
        usable for remote keys: ownerEmail must not be active_user's own."""
        if ownerEmail == UserService().getActiveUser().email:
            raise PermissionError("cannot add your own key to the public key ring")

        pemService = PEMService(key_size=keySize)
        _, publicKeyPem = pemService.importFromFile(publicKeyPath)

        publicKey = serialization.load_pem_public_key(publicKeyPem)
        if publicKey.key_size != keySize:
            raise ValueError(f"imported key size {publicKey.key_size} does not match expected {keySize}")

        keyId = utils.keyIdFromPublicKeyPem(publicKeyPem)

        row = PublicKeyRingRow(
            timestamp=datetime.now(timezone.utc),
            key_id=keyId,
            public_key_pem=publicKeyPem,
            user_email=UserService().getActiveUser().email,
            owner_email=ownerEmail,
            owner_trust=ownerTrust,
            key_legitimacy=0,
            signatures=[],
        )

        self.rows.append(row)
        self._writeRows(self.rows)
        return row

    # -----------------------------------------------------------------
    # delete
    # -----------------------------------------------------------------

    def deleteRow(self, keyId: bytes) -> bool:
        """Delete the row for keyId, only if active_user is its owner (the
        one who added it). Also strips every signature made by that key
        from every other row, and recalculates their keyLegitimacy."""
        row = self._findRowByKeyId(keyId, UserService().getActiveUser().email)
        if row is None:
            return False
        if row.user_email != UserService().getActiveUser().email:
            raise PermissionError("only the row's owner can delete it")

        self.rows.remove(row)
        self._stripSignaturesByKeyId(keyId)
        self._writeRows(self.rows)
        return True

    def deleteAllRowsForKeyId(self, keyId: bytes) -> None:
        """Used when the underlying private key itself is deleted: remove
        every row for this key regardless of who added it, and strip every
        signature made by this key from the remaining rows."""
        self.rows = [row for row in self.rows if row.key_id != keyId]
        self._stripSignaturesByKeyId(keyId)
        self._writeRows(self.rows)

    def _stripSignaturesByKeyId(self, signerKeyId: bytes) -> None:
        for row in self.rows:
            before = len(row.signatures)
            row.signatures = [sig for sig in row.signatures if sig.idpu_signature != signerKeyId]
            if len(row.signatures) != before:
                self._recalculateKeyLegitimacy(row)

    # -----------------------------------------------------------------
    # signing
    # -----------------------------------------------------------------

    def signRow(self, rowOwnerEmail: str, rowKeyId: bytes, signerKeyId: bytes, password: bytes) -> Signature:
        """active_user signs the row identified by rowKeyId, using the key
        pair signerKeyId (must be active_user's own, found via the private
        key ring and decrypted with `password`)."""
        row = self._findRowByKeyId(rowKeyId, rowOwnerEmail)
        if row is None:
            raise ValueError(f"no public key ring row for keyId {rowKeyId.hex()}")

        if not self._canSign(row, signerKeyId):
            raise PermissionError(
                "active_user must own this row, or must have already added the signing key in PubKR"
            )

        privateKeyRing = PrivateKeyRing(self.folderPath)
        privateRow = privateKeyRing.findByKeyId(signerKeyId)
        if privateRow is None:
            raise ValueError(f"no private key ring entry for keyId {signerKeyId.hex()}")

        if any(sig.idpu_signature == signerKeyId for sig in row.signatures):
            raise ValueError("this key has already signed this row")

        privateKeyPem = privateKeyRing.getDecryptedPrivateKeyPem(signerKeyId, password)

        IDPU_signature = signerKeyId
        PU_signature = privateRow.public_key_pem
        IDPU_signed = row.key_id
        signedMessage = self._authService.sign(
            IDPU_signature + PU_signature + IDPU_signed, privateKeyPem
        )

        signature = Signature(
            idpu_signature=IDPU_signature,
            pu_signature=PU_signature,
            idpu_signed=IDPU_signed,
            signature=signedMessage.signature,
            trust=self._signatureTrustFor(row, signerKeyId),
        )

        row.signatures.append(signature)
        self._recalculateKeyLegitimacy(row)
        self._writeRows(self.rows)
        return signature

    def _canSign(self, row: PublicKeyRingRow, signerKeyId: bytes) -> bool:
        activeUserEmail = UserService().getActiveUser().email
        if row.user_email == activeUserEmail:
            return True
        """
        If active user isn't signing his own row, then active user must have a row which was added
        by the current row owner and at the same time it is the exact public key with which you want 
        to sign, because owner trust sets the trust in that specific owners key
        """
        # if active user isn't signing his own row, then active user must have a row which was added
        # by 
        return any(
            other.owner_email == activeUserEmail 
            and other.user_email == row.user_email 
            and signerKeyId == other.key_id
            for other in self.rows
        )

    def _signatureTrustFor(self, row: PublicKeyRingRow, signerKeyId: bytes) -> int:
        """The Owner Trust that row.user_email themselves recorded for the
        signer's key elsewhere in the ring (0 if they never added it)."""
        signerRow = next(
            (r for r in self.rows if r.user_email == row.user_email and r.key_id == signerKeyId),
            None,
        )
        return signerRow.owner_trust if signerRow is not None else 0

    # -----------------------------------------------------------------
    # key legitimacy
    # -----------------------------------------------------------------

    def _recalculateKeyLegitimacy(self, row: PublicKeyRingRow) -> None:
        if row.user_email == UserService().getActiveUser().email:
            row.key_legitimacy = 1
            return

        weightSum = sum(
            FULL_TRUST_WEIGHT if sig.trust >= FULL_TRUST_THRESHOLD else MARGINAL_TRUST_WEIGHT
            for sig in row.signatures
        )
        row.key_legitimacy = 1 if weightSum >= LEGITIMACY_THRESHOLD else 0
