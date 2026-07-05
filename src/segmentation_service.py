"""
Segmentation step of the PGP scheme


Each segment is self-describing: it starts with an 8-byte header carrying its
sequence number and the total number of segments:

    +----------------+----------------+------------------------+
    | index (4 bytes)| total 4 bytes)|   payload (<= maxSize) |
    +----------------+----------------+------------------------+
"""

import struct

DEFAULT_MAX_SEGMENT_SIZE = 50_000

# header = ">II" = index (uint32) + total (uint32)
HEADER_SIZE = 8
_HEADER_FORMAT = ">II"


class SegmentationService:
    def __init__(self, maxSize: int = DEFAULT_MAX_SEGMENT_SIZE):
        if maxSize <= 0:
            raise ValueError("maxSize must be a positive number of bytes")
        self.maxSize = maxSize

    def segment(self, data: bytes) -> list[bytes]:
        """Split data into consecutive segments, each prefixed with its
        (index, total) header."""
        payloads = []
        position = 0
        while position < len(data):
            payload = data[position:position + self.maxSize]
            payloads.append(payload)
            position += self.maxSize
        total = len(payloads)
        return [
            struct.pack(_HEADER_FORMAT, index, total) + payload
            for index, payload in enumerate(payloads)
        ]

    def reassemble(self, segments: list[bytes]) -> bytes:
        """Join segments back in order using their headers. Works regardless of
        the order the segments are given in. Raises ValueError if a segment is
        malformed, or if the set of segments is incomplete/inconsistent."""
        if not segments:
            return b""

        parsed = []          # (index, payload)
        declaredTotals = set()
        for seg in segments:
            if len(seg) < HEADER_SIZE:
                raise ValueError("segment too short to contain a header")
            index, total = struct.unpack(_HEADER_FORMAT, seg[:HEADER_SIZE])
            parsed.append((index, seg[HEADER_SIZE:]))
            declaredTotals.add(total)

        if len(declaredTotals) != 1:
            raise ValueError("segments disagree on the total count")
        total = declaredTotals.pop()

        if len(parsed) != total:
            raise ValueError(f"expected {total} segments, got {len(parsed)}")

        parsed.sort(key=lambda p: p[0])
        indices = [index for index, _ in parsed]
        if indices != list(range(total)):
            raise ValueError("segment indices are not a complete 0..N-1 sequence")

        return b"".join(payload for _, payload in parsed)