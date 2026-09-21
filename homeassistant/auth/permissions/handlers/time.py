"""Time handler for RBAC authorization."""

from datetime import datetime, time
import logging
from typing import Any

from homeassistant.util import dt as dt_util

from ..context import RBACContext
from ..definition import RBACHandlerFrontRequestDefinition
from ..parserRbac import RBACPolicyParser

_LOGGER = logging.getLogger(__name__)


class RBACHandlerTime:
    """Handler for request time."""

    def __init__(self, policy: RBACPolicyParser) -> None:
        """Initialize time handler."""
        self._policy = policy

    async def handle(self, context: RBACContext) -> bool:
        """Handle an authorization request."""

        actual_time = dt_util.now().time()

        try:
            limit_times = self._policy.get_user_attributes(context.user.id, "time")
        except KeyError as error:
            _LOGGER.error(error)
            return False

        # Run through all limit_times
        for limit_time in limit_times:
            start = datetime.strptime(limit_time["start"], "%H:%M").time()
            end = datetime.strptime(limit_time["end"], "%H:%M").time()
            if start <= actual_time <= end:
                return True

        return False

    permission_definition = RBACHandlerFrontRequestDefinition(
        id="time",
        label="Horário",
        type="time_range",
        attribute="time",
    )

    def validate_value(self, value: Any) -> None:
        """Validate value if is dictionary of strings."""
        if not isinstance(value, dict):
            raise TypeError("Time permission must be an object")

        start = value.get("start")
        end = value.get("end")

        if not isinstance(start, str):
            raise TypeError("Time start must be a string")

        if not isinstance(end, str):
            raise TypeError("Time end must be a string")

        try:
            time.fromisoformat(start)
            time.fromisoformat(end)
        except ValueError as error:
            raise ValueError("Invalid time format") from error

    def update_role(self, role: dict[str, Any], value: object) -> None:
        """Update this role time attribute."""
        self.validate_value(value)
        role[self.permission_definition.attribute] = value
