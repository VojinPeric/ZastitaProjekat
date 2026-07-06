"""
pytest tests for CompressionService.
"""

import zlib

import pytest

from services.compression_service import CompressionService


@pytest.fixture
def service():
    return CompressionService()


# payloads covering the shapes that matter: empty, tiny, text, random binary,
# and a large highly-repetitive blob (the case where compression pays off)
PAYLOADS = {
    "empty": b"",
    "one_byte": b"A",
    "short_text": b"hello world",
    "utf8_text": "Zdravo, ovo je PGP poruka sa \u0107irilicom \u0448.".encode("utf-8"),
    "random_binary": bytes(range(256)) * 4,
    "very_repetitive": b"AB" * 10_000,
    "newlines_and_zeros": b"\x00\n\x00\n" * 500,
}


@pytest.mark.parametrize("name", list(PAYLOADS.keys()))
def test_round_trip_restores_original(service, name):
    original = PAYLOADS[name]

    restored = service.decompress(service.compress(original))

    assert restored == original


def test_output_is_bytes(service):
    out = service.compress(b"some data")
    assert isinstance(out, bytes)
    assert isinstance(service.decompress(out), bytes)


def test_empty_input_round_trips(service):
    assert service.decompress(service.compress(b"")) == b""


def test_repetitive_data_gets_smaller(service):
    original = b"AB" * 10_000  # 20 000 bytes, extremely compressible

    compressed = service.compress(original)

    assert len(compressed) < len(original)


def test_has_valid_zlib_header(service):
    """A zlib stream starts with CMF+FLG where the compression method (low
    nibble of CMF) is 8 = DEFLATE, and (CMF*256 + FLG) is a multiple of 31."""
    compressed = service.compress(b"x" * 1000)

    cmf, flg = compressed[0], compressed[1]
    assert (cmf & 0x0F) == 8, "compression method must be DEFLATE"
    assert (cmf * 256 + flg) % 31 == 0, "zlib header check bits must be valid"


def test_can_decompress_external_zlib(service):
    """A zlib stream made by some other tool (here: zlib.compress directly)
    must be readable by our service."""
    original = b"produced elsewhere" * 50
    external = zlib.compress(original)

    assert service.decompress(external) == original
