import zlib


class CompressionService:
    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data)
 
    def decompress(self, data: bytes) -> bytes:
        try:
            return zlib.decompress(data)
        except Exception:
            raise ValueError("Bad format when decompressing message")