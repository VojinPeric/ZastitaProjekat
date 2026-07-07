"""
File containing transition message types between pgp protocol steps.
Since some steps in PGP can be skipped all steps (signature, encryption, etc.) 
should just send array of bytes forward.
"""

from datetime import datetime, timezone
from enum import Enum

ROOT_PATH = "app_data"

class AlgorithmSymmetric(Enum):
    AES = "AES128"
    DES3 = "DES3"

class Message:
    __slots__ = ("msg", "filename", "timestamp")

    def __init__(self):
        self.msg = ""
        self.filename = ""
        self.timestamp = datetime.now(timezone.utc)

class SignedMessage:
    __slots__ = ("rawMessage", "signature", "leadingTwoOctets", "keyId", "timestamp")

    def __init__(self):
        self.rawMessage = bytes()
        self.signature = bytes()
        self.leadingTwoOctets = bytes()
        self.keyId = bytes()
        self.timestamp = datetime.now(timezone.utc)

class EncryptedMessage:
    __slots__ = ("msg", "encryptedSessionKey", "keyId", "algorythm", "iv")

    def __init__(self):
        self.msg = bytes()
        self.encryptedSessionKey = bytes()
        self.iv = bytes()
        self.keyId = bytes()
        self.algorythm = AlgorithmSymmetric.AES
