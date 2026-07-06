"""
pytest tests for CompatibilityService.
"""

import base64

import pytest

from compatibility_service import CompatibilityService


@pytest.fixture
def service():
    return CompatibilityService()


# inputs mirroring the ones used for SegmentationService
PAYLOADS = {
    "empty": b"",
    "ascii_text": b"hello world",
    "binary_with_zeros": bytes(range(256)),
    "single_byte": b"\x00",
}


# ---------------------------------------------------------------------------
# encode / decode
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(PAYLOADS.keys()))
def test_encode_matches_standard_base64(service, name):
    data = PAYLOADS[name]
    assert service.encode(data) == base64.b64encode(data).decode("ascii")


@pytest.mark.parametrize("name", list(PAYLOADS.keys()))
def test_decode_reverses_encode(service, name):
    data = PAYLOADS[name]
    assert service.decode(service.encode(data)) == data


def test_encode_output_is_ascii_str(service):
    encoded = service.encode(b"binary \xff\xfe data")
    assert isinstance(encoded, str)
    encoded.encode("ascii")  # raises if it isn't pure ASCII


# ---------------------------------------------------------------------------
# str <-> bytes helpers (used to feed b64 text into SegmentationService)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(PAYLOADS.keys()))
def test_b64_str_bytes_helpers_round_trip(service, name):
    b64_str = service.encode(PAYLOADS[name])
    as_bytes = service.b64_str_to_bytes(b64_str)
    assert service.bytes_to_b64_str(as_bytes) == b64_str


def test_b64_str_to_bytes_matches_ascii_encoding(service):
    b64_str = service.encode(b"round trip me")
    assert service.b64_str_to_bytes(b64_str) == b64_str.encode("ascii")


# ---------------------------------------------------------------------------
# invalid input
# ---------------------------------------------------------------------------

def test_decode_rejects_invalid_base64(service):
    with pytest.raises(Exception):
        service.decode("not-valid-base64!!!")
