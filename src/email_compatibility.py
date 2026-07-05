"""
PGP's radix-64 conversion step, needed so binary message data can pass
safely through email systems that only support ASCII text.
"""

import base64

def encode(msg: bytes) -> str:
    return base64.b64encode(msg).decode("ascii")

def decode(msg: str) -> bytes:
    return base64.b64decode(msg)
