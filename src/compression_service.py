import zlib


class CompressionService:
    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data)
 
    def decompress(self, data: bytes) -> bytes:
        return zlib.decompress(data)