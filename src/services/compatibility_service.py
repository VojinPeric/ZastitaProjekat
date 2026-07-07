"""
PGP's radix-64 conversion step, needed so binary message data can pass
safely through email systems that only support ASCII text.
"""

import base64

class CompatibilityService:
    def b64_str_to_bytes(self, b64_str: str) -> bytes:
        return b64_str.encode("ascii")


    def bytes_to_b64_str(self, data: bytes) -> str:
        try:
            return data.decode("ascii")
        except Exception:
            raise ValueError("Bad format when decoding message")

    def encode(self, msg: bytes) -> str:
        return base64.b64encode(msg).decode("ascii")

    def decode(self, msg: str) -> bytes:
        try:
            return base64.b64decode(msg)
        except Exception:
            raise ValueError("Bad format when decoding message")
