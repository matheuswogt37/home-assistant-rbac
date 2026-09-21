"""Parser for json that RBAC access control consume."""

import json
import os
from pathlib import Path
import tempfile
from typing import Any

DEFAULT_POLICY: dict[str, Any] = {
    "users": {},
    "roles": {},
}


class RBACPolicyParser:
    """Parse and store the RBAC policy."""

    def __init__(self, path: Path) -> None:
        """Initialize RBAC Json Parser."""
        self._path = path
        self._data: dict[str, Any] = {}

    def _write_policy(self) -> None:
        """Write the current policy atomically."""

        self._path.parent.mkdir(parents=True, exist_ok=True)

        fd, temp_path = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=".rbac-",
            suffix=".tmp",
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(
                    self._data,
                    file,
                    indent=2,
                    ensure_ascii=False,
                )
                file.write("\n")

            os.replace(temp_path, self._path)

        except Exception:
            os.unlink(temp_path)
            raise

    def reset(self) -> None:
        """Reset RBAC policy to default policy."""

        self._data = DEFAULT_POLICY.copy()
        self._write_policy()

    def load(self) -> None:
        """Load the RBAC policy from disk."""

        if not self._path.exists():
            self.reset()

        with self._path.open("r", encoding="utf-8") as file:
            self._data = json.load(file)

    # CRUD

    # Create
    def create_role(self, role: str) -> None:
        """Create a new RBAC role."""

        if not role:
            raise ValueError("Role name cannot be empty")

        roles = self._data.setdefault("roles", {})

        if role in roles:
            raise ValueError(f"Role {role!r} already exists")

        roles[role] = {}

        self._write_policy()

    # Read
    def get_user_attributes(self, user_id: str, attribute: str) -> Any:
        """Get one specific attribute from all user roles."""

        user = self._data.get("users", {}).get(user_id)

        if user is None:
            raise KeyError(
                "User had no roles"
            )  #! On this line is wrong to add user_id to identify the user? For logging purpose
            # Return false because this will be the default return for some error, the requester needs to take care of this

        # All permissions for this user and attribute
        values = []

        roles = user.get("roles", [])

        for role in roles:
            role_data = self._data.get("roles", {}).get(role)

            if role_data is None:
                continue

            if attribute in role_data:
                values.append(role_data[attribute])

        # if there is no attribute on user roles
        if not values:
            raise KeyError(f"Attribute {attribute!r} not found on user roles")

        # Strategy 1: If this attribute contains only boolean then return True if ANY role grants it (Logical OR)
        if all(isinstance(v, bool) for v in values):
            return any(values)

        # Strategy 2: If this attribute contains only lists then flatten and deduplicate
        if all(isinstance(v, list) for v in values):
            unique_items = []
            for sublist in values:
                for item in sublist:
                    if item not in unique_items:
                        unique_items.append(item)
            return unique_items

        # Strategy 3: If this attribute contains only dictionaries/objects (deduplicate dicts)
        if all(isinstance(v, dict) for v in values):
            unique_dicts = []
            for d in values:
                if d not in unique_dicts:
                    unique_dicts.append(d)
            return unique_dicts

        # Default strategy: return what this attribute had, the requester needs to take care of this
        return values

    def get_users(self) -> list[dict[str, Any]]:
        """Get all users and their assigned roles."""
        users = self._data.get("users", {})

        # Return this array using the format that is inside it
        return [
            {
                "user_id": user_id,
                "roles": user_data.get("roles", []),
            }
            for user_id, user_data in users.items()
        ]

    def get_roles(self) -> list[dict[str, Any]]:
        """Get all available roles."""
        return list(self._data.get("roles", {}).keys())

    def get_role(self, role: str) -> dict[str, Any]:
        """Get an RBAC role."""
        roles = self._data.get("roles", {})

        if role not in roles:
            raise KeyError(f"Role {role!r} not found")

        try:
            # Create a new dict from original value (roles[role])
            return dict(roles[role])
        except (TypeError, ValueError) as error:
            raise TypeError(
                f"Role {role!r} data cannot be converted to a dictionary"
            ) from error

    # Update
    def update_users(self, users: list[dict[str, Any]]) -> None:
        """Update users and their assigned roles."""

        available_roles = self._data.get("roles", {})

        updated_users: dict[str, dict[str, Any]] = {}

        for user in users:
            user_id = user.get("user_id")
            roles = user.get("roles", [])

            if not isinstance(user_id, str):
                raise TypeError("User ID must be a string")

            if not isinstance(roles, list):
                raise TypeError("User roles must be a list")

            if not all(isinstance(role, str) for role in roles):
                raise TypeError("User roles must contain only strings")

            invalid_roles = [role for role in roles if role not in available_roles]

            if invalid_roles:
                raise ValueError(f"Unknown roles: {', '.join(invalid_roles)}")

            updated_users[user_id] = {
                "roles": roles,
            }

        self._data["users"] = updated_users

        self._write_policy()

    def update_role(self, role: str, role_data: dict[str, Any]) -> None:
        """Update an RBAC role."""

        roles = self._data.get("roles", {})

        if role not in roles:
            raise KeyError(f"Role {role!r} not found")

        roles[role] = role_data.copy()

        self._write_policy()

    # Delete
    def delete_role(self, role: str) -> None:
        """Delete an RBAC role."""

        roles = self._data.setdefault("roles", {})

        if role not in roles:
            raise ValueError(f"Role {role!r} not found")

        users = self._data.get("users", {})

        users_with_role = [
            user_id
            for user_id, user_data in users.items()
            if role in user_data.get("roles", [])
        ]

        if users_with_role:
            raise ValueError(f"Role {role!r} is assigned to users")

        del roles[role]

        self._write_policy()
