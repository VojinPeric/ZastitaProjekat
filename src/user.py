"""
Local user table for the PGP scheme.

UserRing is a singleton wrapping a users.json file, the same pattern as
PublicKeyRing wraps public_key_ring.json: the first call to
UserRing(folder_path) creates/loads the file, every later call from
anywhere in the process returns that same instance.
"""

import json
import os
from dataclasses import dataclass

RING_FILENAME = "users.json"


@dataclass
class User:
    """The user class (username, email, path to their message box folder)"""
    Username: str
    Email: str
    MessageBoxFolderPath: str

    def to_dict(self) -> dict:
        return {
            "Username": self.Username,
            "Email": self.Email,
            "MessageBoxFolderPath": self.MessageBoxFolderPath,
        }

    @staticmethod
    def from_dict(data: dict) -> "User":
        return User(
            Username=data["Username"],
            Email=data["Email"],
            MessageBoxFolderPath=data["MessageBoxFolderPath"],
        )


class UserRing:
    """Singleton wrapping the local users.json file."""

    _instance = None

    def __new__(cls, folder_path: str):
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._setup(folder_path)
            cls._instance = instance
        return cls._instance

    def _setup(self, folder_path: str) -> None:
        self.folderPath = folder_path
        self.filePath = os.path.join(folder_path, RING_FILENAME)

        os.makedirs(folder_path, exist_ok=True)
        if not os.path.exists(self.filePath):
            self._writeUsers([])

        self.users: list[User] = self._readUsers()

    @classmethod
    def resetSingleton(cls) -> None:
        """Test-only escape hatch: forget the cached instance so a fresh
        folder_path can be used to build a new one."""
        cls._instance = None

    # -----------------------------------------------------------------
    # persistence
    # -----------------------------------------------------------------

    def _readUsers(self) -> list[User]:
        with open(self.filePath, "r", encoding="utf-8") as file:
            data = json.load(file)
        return [User.from_dict(user) for user in data]

    def _writeUsers(self, users: list[User]) -> None:
        with open(self.filePath, "w", encoding="utf-8") as file:
            json.dump([user.to_dict() for user in users], file, indent=2)

    # -----------------------------------------------------------------
    # operations
    # -----------------------------------------------------------------

    def addUser(self, username: str, email: str, messageBoxFolderPath: str) -> User:
        """Add a user, unless the username or email is already taken."""
        if self.findByUsername(username) is not None:
            raise ValueError(f"username '{username}' already exists")
        if self.findByEmail(email) is not None:
            raise ValueError(f"email '{email}' already exists")

        user = User(Username=username, Email=email, MessageBoxFolderPath=messageBoxFolderPath)
        self.users.append(user)
        self._writeUsers(self.users)
        return user

    def findByUsername(self, username: str) -> User | None:
        return next((user for user in self.users if user.Username == username), None)

    def findByEmail(self, email: str) -> User | None:
        return next((user for user in self.users if user.Email == email), None)


active_user: User = None
