"""
pytest tests for SegmentationService.
"""

import random
import struct

import pytest

from segmentation_service import (
    SegmentationService,
    DEFAULT_MAX_SEGMENT_SIZE,
    HEADER_SIZE,
)


@pytest.fixture
def service():
    return SegmentationService(maxSize=10)


# inputs relative to a maxSize of 10
PAYLOADS = {
    "empty": b"",
    "smaller_than_one_segment": b"abc",
    "exactly_one_segment": b"0123456789",
    "one_over_a_segment": b"0123456789X",
    "several_full_segments": b"0123456789" * 5,
    "several_plus_remainder": b"0123456789" * 3 + b"tail",
    "binary_with_zeros": bytes(range(256)),
}


# ---------------------------------------------------------------------------
# round trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(PAYLOADS.keys()))
def test_round_trip_in_order(service, name):
    original = PAYLOADS[name]
    assert service.reassemble(service.segment(original)) == original


@pytest.mark.parametrize("name", list(PAYLOADS.keys()))
def test_round_trip_when_shuffled(service, name):
    """The whole point of the header: order survives even if segments are
    delivered out of order."""
    original = PAYLOADS[name]
    segments = service.segment(original)

    shuffled = segments[:]
    random.Random(42).shuffle(shuffled)

    assert service.reassemble(shuffled) == original


# ---------------------------------------------------------------------------
# segment sizing / structure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(PAYLOADS.keys()))
def test_payload_never_exceeds_max(service, name):
    for seg in service.segment(PAYLOADS[name]):
        payload = seg[HEADER_SIZE:]
        assert len(payload) <= service.maxSize


def test_headers_carry_correct_index_and_total(service):
    data = b"0123456789" * 3 + b"tail"  # 34 bytes -> 4 segments (10,10,10,4)
    segments = service.segment(data)

    assert len(segments) == 4
    for expectedIndex, seg in enumerate(segments):
        index, total = struct.unpack(">II", seg[:HEADER_SIZE])
        assert index == expectedIndex
        assert total == 4


def test_segment_count_is_ceiling(service):
    data = b"x" * 25  # 25 / 10 -> 3 segments
    assert len(service.segment(data)) == 3


def test_data_shorter_than_max_is_single_segment(service):
    segments = service.segment(b"short")
    assert len(segments) == 1
    assert segments[0][HEADER_SIZE:] == b"short"


def test_empty_input_produces_no_segments(service):
    assert service.segment(b"") == []
    assert service.reassemble([]) == b""


# ---------------------------------------------------------------------------
# validation of a bad segment set
# ---------------------------------------------------------------------------

def test_missing_segment_is_detected(service):
    segments = service.segment(b"0123456789" * 3)  # 3 segments
    del segments[1]                                 # drop the middle one
    with pytest.raises(ValueError):
        service.reassemble(segments)


def test_duplicate_segment_is_detected(service):
    segments = service.segment(b"0123456789" * 3)  # 3 segments
    segments[2] = segments[0]                       # duplicate index 0, lose index 2
    with pytest.raises(ValueError):
        service.reassemble(segments)


def test_inconsistent_total_is_detected(service):
    segments = service.segment(b"0123456789" * 2)   # total = 2 in both headers
    # tamper one header to claim a different total
    bad = struct.pack(">II", 1, 99) + segments[1][HEADER_SIZE:]
    with pytest.raises(ValueError):
        service.reassemble([segments[0], bad])


def test_truncated_header_is_detected(service):
    with pytest.raises(ValueError):
        service.reassemble([b"\x00\x01"])  # shorter than HEADER_SIZE


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def test_default_max_segment_size_is_used():
    service = SegmentationService()
    assert service.maxSize == DEFAULT_MAX_SEGMENT_SIZE


def test_invalid_max_size_rejected():
    with pytest.raises(ValueError):
        SegmentationService(maxSize=0)
    with pytest.raises(ValueError):
        SegmentationService(maxSize=-5)


def test_large_input_round_trips_with_default_size():
    service = SegmentationService()  # 50 000
    data = b"A" * 120_000            # spans multiple segments
    segments = service.segment(data)
    assert len(segments) == 3
    assert service.reassemble(segments) == data