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

    # Update

    # Delete
