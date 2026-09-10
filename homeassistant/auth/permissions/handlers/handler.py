"""Base RBAC Handler class."""

from typing import Protocol

from ..context import RBACContext


class RBACHandler(Protocol):
    """Base class for RBAC chain handlers."""

    async def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""
