"""Network handler for RBAC authorization."""

import ipaddress
import logging
from typing import Any

from ..context import RBACContext
from ..definition import RBACHandlerFrontRequestDefinition
from ..parserRbac import ATTRIBUTE_NOT_FOUND, RBACPolicyParser

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
        default_subnets = ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for net in default_subnets:
            try:
                self._allowed_networks.append(ipaddress.ip_network(net, strict=False))
            except ValueError as err:
                _LOGGER.error(err)

    def is_on_local_network(self, ip_str: str | None) -> bool:
        """Checks if an IP address string belongs to a local/private network, including loopback and link-local addresses."""
        if ip_str is None:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            # Returns False if the string is not a valid IP address
            return False

        if ip.is_loopback:
            return True

        return any(ip in network for network in self._allowed_networks)

    def _extract_ip_from_connection(self, context: RBACContext) -> str | None:
        """Extracts client IP address safely from ActiveConnection context."""
        conn = context.connection
        if not conn:
            return None

        if hasattr(conn, "ip_address") and conn.ip_address:
            return str(conn.ip_address)

        if hasattr(conn, "remote"):
            return str(conn.remote)

        if hasattr(conn, "ws") and hasattr(conn.ws, "remote_address"):
            return str(conn.ws.remote_address[0])

        return None

    def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

        try:
            network = self._policy.get_user_attributes(
                context.user.id, self.permission_definition.attribute
            )
        except KeyError as error:
            _LOGGER.error(error)
            return False

        # If this user had no attribute related then permit
        if network is ATTRIBUTE_NOT_FOUND:
            return True

        if not network:
            return True

        client_ip = self._extract_ip_from_connection(context)
        if not client_ip:
            return False

        is_local = self.is_on_local_network(client_ip)
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
            role.pop(self.permission_definition.attribute, None)
            return
        role[self.permission_definition.attribute] = value
