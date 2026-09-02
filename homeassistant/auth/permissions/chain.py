from collections.abc import Sequence

from .context import RBACContext
from .parserRbac import RBACPolicyParser

# RBAC handlers
from .handlers.permission import RBACHandlerPermission
from .handlers.time import RBACHandlerTime

class RBACChain:
    """Chain of Responsibility for RBAC authorization."""

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Initialize the RBAC chain."""
        self._handlers = [
            RBACHandlerPermission(policy),
            RBACHandlerTime(policy)
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