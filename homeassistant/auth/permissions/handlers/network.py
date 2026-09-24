"""Network handler for RBAC authorization."""

import ipaddress
import logging
from typing import Any

from ..context import RBACContext
from ..definition import RBACHandlerFrontRequestDefinition
from ..parserRbac import RBACPolicyParser

_LOGGER = logging.getLogger(__name__)


class RBACHandlerNetwork:
    """Handler for request network."""

    permission_definition = RBACHandlerFrontRequestDefinition(
        id="network",
        label="Rede local",
        type="boolean",
        attribute="only_local_network",
    )

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Initialize network handler."""
        self._policy = policy

    def is_on_local_network(self, ip_str: str | None) -> bool:
        """Checks if an IP address string belongs to a local/private network, including loopback and link-local addresses."""
        if ip_str is None:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            # Returns False if the string is not a valid IP address
            return False
        else:
            return ip.is_private or ip.is_loopback or ip.is_link_local

    def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

        try:
            network = self._policy.get_user_attributes(
                context.user.id, self.permission_definition.attribute
            )
        except KeyError as error:
            _LOGGER.error(error)

        if not network:
            return True

        is_local = self.is_on_local_network(context.connection.remote)
        if is_local:
            return True

        return False

    def validate_value(self, value: Any) -> None:
        """Validate value if is bool."""
        if not isinstance(value, bool):
            raise TypeError("Network permission must be a boolean")

    def update_role(self, role: dict[str, Any], value: object) -> None:
        """Update this role network attribute."""
        self.validate_value(value)
        if not value:
            role.pop(self.permission_definition.attribute)
            return
        role[self.permission_definition.attribute] = value
