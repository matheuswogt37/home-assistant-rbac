from datetime import datetime
from homeassistant.util import dt as dt_util

from ..context import RBACContext
from ..parserRbac import RBACPolicyParser

class RBACHandlerTime():
    """Handler for request time."""
    
    def __init__(self, policy: RBACPolicyParser) -> None:
        self._policy = policy

    async def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

        actual_time = dt_util.now().time()

        try:
            limit_times = self._policy._get_user_attributes(context.user.id, "time")
        except KeyError as error:
            print(error)
            return False

        # Run through all limit_times
        for time in limit_times:
            start = datetime.strptime(time["start"], "%H:%M").time()
            end = datetime.strptime(time["end"], "%H:%M").time()
            if start <= actual_time <= end:
                return True

        return False