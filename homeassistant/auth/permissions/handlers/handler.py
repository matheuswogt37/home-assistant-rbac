from typing import Protocol

from ..context import RBACContext
from ..parserRbac import RBACPolicyParser


class RBACHandler(Protocol):
    """Base class for RBAC chain handlers."""

    def __init__(self, policy: RBACPolicyParser) -> None:
        self._policy = policy

    async def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""