"""RBAC authorization chain execution module."""

from copy import deepcopy
import logging
from typing import Any

from .context import RBACContext

# RBAC frontend handler request definition
from .definition import RBACHandlerFrontRequestDefinition
from .handlers.handler import RBACHandler
from .handlers.network import RBACHandlerNetwork

# RBAC handlers
from .handlers.permission import RBACHandlerPermission
from .handlers.time import RBACHandlerTime
from .parserRbac import RBACPolicyParser

_LOGGER = logging.getLogger(__name__)


class RBACChain:
    """Chain of Responsibility for RBAC authorization."""

    _handlers: list[RBACHandler] = []
    _policy: RBACPolicyParser

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Initialize the RBAC chain."""
        self._handlers = [
            RBACHandlerPermission(policy),
            RBACHandlerTime(policy),
            RBACHandlerNetwork(policy),
        ]
        self._policy = policy

    def handle(self, context: RBACContext) -> bool:
        """Run all authorization handlers."""

        # If this user had administration access then permit all actions
        if context.user.is_admin:
            return True

        return all(handler.handle(context) for handler in self._handlers)

    def get_permission_definitions(self) -> list[RBACHandlerFrontRequestDefinition]:
        """Return the definitions of all RBAC permissions."""
        return [handler.permission_definition for handler in self._handlers]

    def get_role_permissions(self, role: str) -> dict[str, Any]:
        """Get a role's permissions using semantic permission IDs."""

        role_data = self._policy.get_role(role)

        permissions: dict[str, Any] = {}

        for definition in self.get_permission_definitions():
            if definition.attribute in role_data:
                permissions[definition.id] = role_data[definition.attribute]

        return permissions

    def update_role_permissions(self, role: str, permissions: dict[str, Any]) -> None:
        """Validate and update all permissions for a role."""

        current_role = self._policy.get_role(role)
        updated_role = deepcopy(current_role)

        handlers_by_id = {
            handler.permission_definition.id: handler for handler in self._handlers
        }

        for permission_id, value in permissions.items():
            handler = handlers_by_id.get(permission_id)

            if handler is None:
                raise ValueError(f"Unknown permission: {permission_id!r}")

            try:
                handler.update_role(updated_role, value)
            except Exception as error:
                _LOGGER.error("Error when updating role: %s", error)
                raise

        try:
            self._policy.update_role(role, updated_role)
        except Exception as error:
            _LOGGER.error("Error when updating role: %s", error)
            raise
