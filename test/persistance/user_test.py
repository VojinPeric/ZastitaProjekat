"""
pytest tests for UserRing / User.
"""

import json

import pytest

from persistance.user import UserRing


# ---------------------------------------------------------------------------
# add / lookup
# ---------------------------------------------------------------------------

def test_add_user_returns_populated_user(ring_folder):
    ring = UserRing(ring_folder)
    user = ring.addUser("alice", "alice@example.com", "/mailbox/alice")

    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.message_box_folder_path == "/mailbox/alice"


def test_duplicate_username_rejected(ring_folder):
    ring = UserRing(ring_folder)
    ring.addUser("alice", "alice@example.com", "/mailbox/alice")

    with pytest.raises(ValueError):
        ring.addUser("alice", "someone-else@example.com", "/mailbox/other")


def test_duplicate_email_rejected(ring_folder):
    ring = UserRing(ring_folder)
    ring.addUser("alice", "alice@example.com", "/mailbox/alice")

    with pytest.raises(ValueError):
        ring.addUser("someone-else", "alice@example.com", "/mailbox/other")


def test_find_by_username_and_email(ring_folder):
    ring = UserRing(ring_folder)
    user = ring.addUser("alice", "alice@example.com", "/mailbox/alice")

    assert ring.findByUsername("alice") is user
    assert ring.findByEmail("alice@example.com") is user
    assert ring.findByUsername("nobody") is None
    assert ring.findByEmail("nobody@example.com") is None


# ---------------------------------------------------------------------------
# JSON persistence
# ---------------------------------------------------------------------------

def test_users_file_has_expected_json_shape(ring_folder):
    ring = UserRing(ring_folder)
    ring.addUser("alice", "alice@example.com", "/mailbox/alice")

    with open(ring.filePath, "r", encoding="utf-8") as file:
        data = json.load(file)

    assert data == [{
        "Username": "alice",
        "Email": "alice@example.com",
        "MessageBoxFolderPath": "/mailbox/alice",
    }]


def test_users_reload_from_disk_after_singleton_reset(ring_folder):
    ring = UserRing(ring_folder)
    ring.addUser("alice", "alice@example.com", "/mailbox/alice")

    UserRing.resetSingleton()
    reloaded = UserRing(ring_folder)

    assert len(reloaded.users) == 1
    assert reloaded.users[0].username == "alice"
    assert reloaded.users[0].email == "alice@example.com"
    assert reloaded.users[0].message_box_folder_path == "/mailbox/alice"
