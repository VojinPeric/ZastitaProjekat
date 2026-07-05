"""
File containing transition message types between pgp protocol steps
"""

class Message:
    __slots__ = ("header", "body")

    def __init__(self):
        self.header = ""
        self.body = ""

class SignedMessage:
    __slots__ = ("rawMessage", "signature")

    def __init__(self):
        self.rawMessage = {}
        self.signature = ""

class CompressedMessage:
    __slots__ = ("msg")

    def __init__(self):
        self.msg = ""

class EncryptedMessage:
    __slots__ = ("msg")

    def __init__(self):
        self.msg = ""

class EncodedMessage:
    __slots__ = ("msg")

    def __init__(self):
        self.msg = ""

class SegmentatedMessage:
    __slots__ = ("parts")

    def __init__(self):
        self.parts = []
