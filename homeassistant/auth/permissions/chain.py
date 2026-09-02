"""RBAC authorization chain execution module."""

from .context import RBACContext
from .handlers.handler import RBACHandler
from .handlers.network import RBACHandlerNetwork

# RBAC handlers
from .handlers.permission import RBACHandlerPermission
from .handlers.time import RBACHandlerTime
from .parserRbac import RBACPolicyParser


class RBACChain:
    """Chain of Responsibility for RBAC authorization."""

    _handlers: list[RBACHandler] = []

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Initialize the RBAC chain."""
        self._handlers = [
            RBACHandlerPermission(policy),
            RBACHandlerTime(policy),
            RBACHandlerNetwork(policy),
        ]

    async def handle(self, context: RBACContext) -> bool:
        """Run all authorization handlers."""

        # If this user had administration access then permit all actions
        if context.user.is_admin:
            return True

        for handler in self._handlers:
            # If this handler DENY this action then return False
            if not await handler.handle(context):
                return False

        #! Think about it
        return True
