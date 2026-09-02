from datetime import datetime
from homeassistant.util import dt as dt_util

from ..context import RBACContext
from ..parserRbac import RBACPolicyParser

class RBACHandlerNetwork():
    """Handler for request network."""
    
    def __init__(self, policy: RBACPolicyParser) -> None:
        self._policy = policy

    async def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

        
        network = self._policy._get_user_attributes(context.user.id, "local_network")
        

        

        return False