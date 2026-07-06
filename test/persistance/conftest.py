"""
Shared fixtures for persistance-layer tests.
"""

import pytest

from persistance import user as user_module
from persistance.user import UserRing
from persistance.private_key_ring import PrivateKeyRing
from persistance.public_key_ring import PublicKeyRing


@pytest.fixture(autouse=True)
def reset_ring_singletons():
    """Every test gets a fresh set of ring singletons and no active user,
    since the rings cache themselves as process-wide singletons."""
    UserRing.resetSingleton()
    PrivateKeyRing.resetSingleton()
    PublicKeyRing.resetSingleton()
    user_module.active_user = None
    yield
    UserRing.resetSingleton()
    PrivateKeyRing.resetSingleton()
    PublicKeyRing.resetSingleton()
    user_module.active_user = None


@pytest.fixture
def ring_folder(tmp_path):
    return str(tmp_path)


@pytest.fixture
def active_user(ring_folder):
    """Registers 'alice' in UserRing and makes her the active user."""
    ring = UserRing(ring_folder)
    user = ring.addUser("alice", "alice@example.com", ring_folder)
    user_module.active_user = user
    return user


@pytest.fixture
def second_user(ring_folder):
    """Registers 'bob' in the same UserRing, without switching active_user."""
    ring = UserRing(ring_folder)
    return ring.addUser("bob", "bob@example.com", ring_folder)
