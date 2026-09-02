"""Request Context to RBAC chain and handlers consume."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant

if TYPE_CHECKING:
    from homeassistant.auth.models import User
    from homeassistant.components.websocket_api import ActiveConnection


@dataclass(slots=True)
class RBACContext:
    """Context for an RBAC authorization request."""

    hass: HomeAssistant
    connection: ActiveConnection
    user: User
    message: dict[str, Any]
