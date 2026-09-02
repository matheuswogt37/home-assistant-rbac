"""Device Permission handler for RBAC authorization."""

import logging

from ..context import RBACContext
from ..parserRbac import RBACPolicyParser

_LOGGER = logging.getLogger(__name__)


class RBACHandlerPermission:
    """Handler for device permissions."""

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Initialize device permission handler."""
        self._policy = policy

    async def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

        device_id = context.message.get("service_data", {}).get("entity_id")
        if device_id is None:
            return False

        try:
            devices = self._policy.get_user_attributes(context.user.id, "attr_devices")
        except KeyError as error:
            _LOGGER.error(error)
            return False

        # If this device_id is on authorized devices then permit, else deny
        if device_id in devices:
            return True

        return False
