from dataclasses import dataclass
from typing import Any

from homeassistant.core import HomeAssistant

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.auth.models import User
    from homeassistant.components.websocket_api.connection import ActiveConnection


@dataclass(slots=True)
class RBACContext:
    """Context for an RBAC authorization request."""

    hass: HomeAssistant
    connection: ActiveConnection
    user: User | None
    message: dict[str, Any]