"""
Top-level PGP service.

Orchestrates the send/receive pipeline for the currently active user, composing
the per-step services rather than reimplementing them. Which steps run is
configurable through PgpStep

Send order follows the PGP scheme: authentication (sign) -> compression ->
encryption (confidentiality) -> radix-64 conversion. Receive reverses it.

On-disk message format (see _packContainer/_unpackContainer):
|magic (4)|flags (1)|payload (rest)|

`flags` is the PgpStep value of the steps that were actually applied.
"""

import os
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Flag

from pgp_messages import Message, AlgorithmSymmetric
from persistance.user import UserService
from persistance.private_key_ring import PrivateKeyRing
from persistance.public_key_ring import PublicKeyRing, PublicKeyRingRow
from services.authentication_service import (
    AuthenticationService,
    toBytesFromSignedMessage,
    fromBytesToSignedMessage,
)
from services.encryption_service import (
    EncryptionService,
    toBytesFromEncryptedMessage,
    fromBytesToEncryptedMessage,
)
from services.compression_service import CompressionService
from services.compatibility_service import CompatibilityService
from pgp_messages import ROOT_PATH

KEY_RING_DIRNAME = "KEY_RINGS"

# container framing
MAGIC = b"PGP1"
_FLAGS_FORMAT = ">B"

# innermost Message framing: timestamp (uint32) + filename length (uint16),
# then the filename and the message body
_MESSAGE_HEADER_FORMAT = ">IH"
_MESSAGE_HEADER_SIZE = 6

class PgpStep(Flag):
    """Which transformation steps of the PGP pipeline to apply. Combine with
    `|` (e.g. PgpStep.AUTHENTICATION | PgpStep.ENCRYPTION); PgpStep.NONE is a
    plain pass-through, PgpStep.ALL runs the whole pipeline."""
    NONE = 0
    AUTHENTICATION = 1
    COMPRESSION = 2
    ENCRYPTION = 4
    CONVERSION = 8
    ALL = AUTHENTICATION | COMPRESSION | ENCRYPTION | CONVERSION


@dataclass
class ReceiveResult:
    """Outcome of receive(): the recovered message plus what was done to it and,
    if it was signed, whether the signature checks out and who signed it."""
    message: Message
    applied_steps: PgpStep
    signature_valid: bool | None   # None when the message was not signed
    signer_key_id: bytes | None
    signer_email: str | None


class PgpService:
    """
    Per-user entry point to the PGP pipeline. Everything belonging to a user
    lives under <root_path>/<user email>/:

        <root_path>/<email>/
            <message files> -> received messages, chosen by the user

    User must be logged in before a PgpService is created. `steps` is the default
    selection of pipeline steps; send() can override it per message.
    """

    def __init__(self, steps: PgpStep = PgpStep.NONE):
        self._userService = UserService()
        activeUser = self._userService.getActiveUser()
        if activeUser is None:
            raise ValueError("no active user; log in through UserService before creating a PgpService")

        self.steps = steps

        keyRingFolder = os.path.join(ROOT_PATH, KEY_RING_DIRNAME)

        self._privateKeyRing = PrivateKeyRing(keyRingFolder)
        self._publicKeyRing = PublicKeyRing(keyRingFolder)
        self._authenticationService = AuthenticationService()
        self._encryptionService = EncryptionService()
        self._compressionService = CompressionService()
        self._compatibilityService = CompatibilityService()

    # -----------------------------------------------------------------
    # send
    # -----------------------------------------------------------------

    def send(
        self,
        message: str,
        output_file_path: str, # should be usernmame or email
        *,
        filename: str = "",
        steps: PgpStep | None = None,
        signer_key_id: bytes | None = None,
        signer_password: bytes | None = None,
        recipient_key_id: bytes | None = None,
        algorithm: AlgorithmSymmetric = AlgorithmSymmetric.AES,
    ) -> None:
        """Protect `message` according to `steps` (defaults to self.steps) and
        write the resulting self-describing packet to `output_file_path`.

        Signing (AUTHENTICATION) needs signer_key_id + signer_password - a key
        pair from the active user's own private ring. Encryption (ENCRYPTION)
        needs recipient_key_id - a public key known to the active user (their
        own, or one imported into the public ring) - and a symmetric algorithm.
        """
        steps = self.steps if steps is None else steps

        messageObj = Message()
        messageObj.msg = message
        messageObj.filename = filename
        payload = _toBytesFromMessage(messageObj)

        appliedSteps = PgpStep.NONE

        if bool(steps & PgpStep.AUTHENTICATION):
            if signer_key_id is None or signer_password is None:
                raise ValueError("signing requires signer_key_id and signer_password")
            privateKeyPem = self._privateKeyRing.getDecryptedPrivateKeyPem(signer_key_id, signer_password)
            signed = self._authenticationService.sign(payload, privateKeyPem)
            payload = toBytesFromSignedMessage(signed)
            appliedSteps |= PgpStep.AUTHENTICATION

        if bool(steps & PgpStep.COMPRESSION):
            payload = self._compressionService.compress(payload)
            appliedSteps |= PgpStep.COMPRESSION

        if bool(steps & PgpStep.ENCRYPTION):
            if recipient_key_id is None:
                raise ValueError("encryption requires recipient_key_id")
            recipientPublicKeyRow = self._findPublicKeyRingRow(recipient_key_id)
            if recipientPublicKeyRow is None:
                raise ValueError(f"no public key found for keyId {recipient_key_id.hex()}")
            encrypted = self._encryptionService.encrypt(payload, recipientPublicKeyRow.public_key_pem, algorithm)
            payload = toBytesFromEncryptedMessage(encrypted)
            appliedSteps |= PgpStep.ENCRYPTION

        if bool(steps & PgpStep.CONVERSION):
            payload = self._compatibilityService.encode(payload).encode("ascii")
            appliedSteps |= PgpStep.CONVERSION

        with open(output_file_path, "wb") as file: # filename should be what is output_file_name now
            file.write(_packContainer(appliedSteps, payload))

    # -----------------------------------------------------------------
    # receive
    # -----------------------------------------------------------------

    def receive(self, input_file_path: str, *, password: bytes | None = None) -> ReceiveResult:
        """Read the packet at `input_file_path`, reverse whatever steps it
        records, and return the recovered message plus verification info.

        Decryption needs `password` for the active user's private key. Raises
        ValueError with a clear message if the file is unrecognized or
        decryption/decompression fails; signature failure is reported (not
        raised) via ReceiveResult.signature_valid.
        """
        with open(input_file_path, "rb") as file:
            data = file.read()

        appliedSteps, payload = _unpackContainer(data)

        if bool(appliedSteps & PgpStep.CONVERSION):
            payload = self._compatibilityService.decode(payload.decode("ascii"))

        if bool(appliedSteps & PgpStep.ENCRYPTION):
            payload = self._decrypt(payload, password)

        if bool(appliedSteps & PgpStep.COMPRESSION):
            try:
                payload = self._compressionService.decompress(payload)
            except Exception as error:
                raise ValueError(f"decompression failed: {error}") from error

        signature_valid: bool | None = None
        signer_key_id: bytes | None = None
        signer_email: str | None = None

        if bool(appliedSteps & PgpStep.AUTHENTICATION):
            signed = fromBytesToSignedMessage(payload)
            signer_key_id = signed.keyId
            signer_email = self._emailForKeyId(signed.keyId)
            signerPublicKeyRow = self._findPublicKeyRingRow(signed.keyId)
            if signerPublicKeyRow is None or signerPublicKeyRow.key_legitimacy != 1:
                signature_valid = False
            else:
                 signature_valid = self._authenticationService.verify(
                     signed, signerPublicKeyRow.public_key_pem)
            payload = signed.rawMessage

        return ReceiveResult(
            message=_fromBytesToMessage(payload),
            applied_steps=appliedSteps,
            signature_valid=signature_valid,
            signer_key_id=signer_key_id,
            signer_email=signer_email,
        )

    # -----------------------------------------------------------------
    # helpers
    # -----------------------------------------------------------------

    def _decrypt(self, payload: bytes, password: bytes | None) -> bytes:
        encrypted = fromBytesToEncryptedMessage(payload)
        if self._privateKeyRing.findByKeyId(encrypted.keyId) is None:
            raise ValueError(
                "decryption failed: no private key in your ring matches this message; "
                "you may not be the intended recipient"
            )
        if password is None:
            raise ValueError("this message is encrypted; a private key password is required to decrypt it")
        try:
            privateKeyPem = self._privateKeyRing.getDecryptedPrivateKeyPem(encrypted.keyId, password)
            return self._encryptionService.decrypt(encrypted, privateKeyPem)
        except Exception as error:
            raise ValueError(f"decryption failed: {error}") from error

    def _findPublicKeyRingRow(self, keyId: bytes) -> PublicKeyRingRow | None:
        """The public key PEM for keyId, in public key ring of active user."""
        importedRow = self._publicKeyRing.getRowByKeyId(keyId)
        if importedRow is not None:
            return importedRow
        return None

    def _emailForKeyId(self, keyId: bytes) -> str | None:
        """The email associated with keyId: the key owner for an imported key."""
        importedRow = self._publicKeyRing.getRowByKeyId(keyId)
        if importedRow is not None:
            return importedRow.owner_email
        return None


# ---------------------------------------------------------------------
# container framing
# ---------------------------------------------------------------------

def _packContainer(appliedSteps: PgpStep, payload: bytes) -> bytes:
    return MAGIC + struct.pack(_FLAGS_FORMAT, appliedSteps.value) + payload


def _unpackContainer(data: bytes) -> tuple[PgpStep, bytes]:
    header_size = len(MAGIC) + 1
    if len(data) < header_size or data[:len(MAGIC)] != MAGIC:
        raise ValueError("unrecognized file: not a PGP message produced by this application")
    flags = struct.unpack(_FLAGS_FORMAT, data[len(MAGIC):header_size])[0]
    try:
        appliedSteps = PgpStep(flags)
    except ValueError as error:
        raise ValueError(f"corrupt PGP message: unknown step flags {flags:#04x}") from error
    return appliedSteps, data[header_size:]


# ---------------------------------------------------------------------
# innermost Message framing
# ---------------------------------------------------------------------

def _toBytesFromMessage(message: Message) -> bytes:
    filenameBytes = message.filename.encode("utf-8")
    messageBytes = message.msg.encode("utf-8")
    timestamp = int(message.timestamp.timestamp())
    return (
        struct.pack(_MESSAGE_HEADER_FORMAT, timestamp, len(filenameBytes))
        + filenameBytes
        + messageBytes
    )


def _fromBytesToMessage(data: bytes) -> Message:
    timestamp, filenameLen = struct.unpack(_MESSAGE_HEADER_FORMAT, data[:_MESSAGE_HEADER_SIZE])
    offset = _MESSAGE_HEADER_SIZE
    filename = data[offset:offset + filenameLen].decode("utf-8")
    offset += filenameLen

    message = Message()
    message.timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    message.filename = filename
    message.msg = data[offset:].decode("utf-8")
    return message
