"""
Shared fixtures for persistance-layer tests.
"""

import pytest

from persistance.user import UserRing, UserService
from persistance.private_key_ring import PrivateKeyRing
from persistance.public_key_ring import PublicKeyRing


@pytest.fixture(autouse=True)
def reset_ring_singletons():
    """Every test gets a fresh set of ring singletons and no active user,
    since the rings (and UserService) cache themselves as process-wide
    singletons."""
    UserRing.resetSingleton()
    PrivateKeyRing.resetSingleton()
    PublicKeyRing.resetSingleton()
    UserService.resetSingleton()
    yield
    UserRing.resetSingleton()
    PrivateKeyRing.resetSingleton()
    PublicKeyRing.resetSingleton()
    UserService.resetSingleton()


@pytest.fixture
def ring_folder(tmp_path):
    return str(tmp_path)


@pytest.fixture
def active_user(ring_folder):
    """Registers 'alice' in UserRing and makes her the active user."""
    ring = UserRing(ring_folder)
    user = ring.addUser("alice", "alice@example.com", ring_folder)
    UserService().login(user.username)
    return user


@pytest.fixture
def second_user(ring_folder):
    """Registers 'bob' in the same UserRing, without making him active."""
    ring = UserRing(ring_folder)
    return ring.addUser("bob", "bob@example.com", ring_folder)
