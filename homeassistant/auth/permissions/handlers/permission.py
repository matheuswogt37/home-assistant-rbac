"""Device Permission handler for RBAC authorization."""

import logging
from typing import Any

from ..context import RBACContext
from ..definition import RBACHandlerFrontRequestDefinition
from ..parserRbac import RBACPolicyParser

_LOGGER = logging.getLogger(__name__)


class RBACHandlerPermission:
    """Handler for device permissions."""

    permission_definition = RBACHandlerFrontRequestDefinition(
        id="device",
        label="Dispositivos",
        type="device_selector",
        attribute="attr_devices",
    )

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Initialize device permission handler."""
        self._policy = policy

    def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

        device_id = context.message.get("service_data", {}).get("entity_id")
        if device_id is None:
            return False

        try:
            devices = self._policy.get_user_attributes(
                context.user.id, self.permission_definition.attribute
            )
        except KeyError as error:
            _LOGGER.error(error)
            return False

        # If this device_id is on authorized devices then permit, else deny
        if device_id in devices:
            return True

        return False

    def validate_value(self, value: Any) -> None:
        """Validate value if is list."""
        if not isinstance(value, list):
            raise TypeError("Device permission must be a list")

        if not all(isinstance(device, str) for device in value):
            raise ValueError("Device permission must contain only strings")

    def update_role(self, role: dict[str, Any], value: object) -> None:
        """Update this role permission attribute."""
        self.validate_value(value)

        if value is None or (hasattr(value, "__len__") and len(value) == 0):
            role.pop(self.permission_definition.attribute)
            return

        role[self.permission_definition.attribute] = value
