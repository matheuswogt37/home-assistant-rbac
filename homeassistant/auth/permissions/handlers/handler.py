"""Base RBAC Handler class."""

from typing import Any, Protocol

from ..context import RBACContext
from ..definition import RBACHandlerFrontRequestDefinition
from ..parserRbac import RBACPolicyParser


class RBACHandler(Protocol):
    """Base class for RBAC chain handlers."""

    permission_definition: RBACHandlerFrontRequestDefinition = (
        RBACHandlerFrontRequestDefinition(
            id="id for this handler",
            label="Device name",
            type="input type",
            attribute="attribute that will be saved and queried on json",
        )
    )

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Init handle."""

    def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

    def validate_value(self, value: Any) -> None:
        """Validate value."""

    def update_role(self, role: dict[str, Any], value: object) -> None:
        """Update this role based on this handler."""
