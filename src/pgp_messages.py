"""
File containing transition message types between pgp protocol steps.
Since some steps in PGP can be skipped all steps (signature, encryption, etc.) 
should just send array of bytes forward.
"""

from datetime import datetime, timezone

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
    __slots__ = ("msg", "encryptedSessionKey", "keyId")

    def __init__(self):
        self.msg = bytes()
        self.encryptedSessionKey = bytes()
        self.keyId = bytes()
