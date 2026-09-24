"""Permissions for Home Assistant."""

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any, override

import voluptuous as vol

from homeassistant.core import HomeAssistant

from .chain import RBACChain
from .const import CAT_ENTITIES
from .context import RBACContext
from .entities import ENTITY_POLICY_SCHEMA, compile_entities
from .merge import merge_policies
from .models import PermissionLookup
from .parserRbac import RBACPolicyParser
from .types import PolicyType
from .util import test_all

if TYPE_CHECKING:
    from homeassistant.components.websocket_api import ActiveConnection

    from ..models import User

POLICY_SCHEMA = vol.Schema({vol.Optional(CAT_ENTITIES): ENTITY_POLICY_SCHEMA})

__all__ = [
    "POLICY_SCHEMA",
    "AbstractPermissions",
    "OwnerPermissions",
    "PermissionLookup",
    "PolicyPermissions",
    "PolicyType",
    "filter_entity_ids_by_permission",
    "merge_policies",
]

ACCESS_CONTROL_DOMAIN = "rbac"


def filter_entity_ids_by_permission(
    user: User, entity_ids: Iterable[str], key: str
) -> list[str]:
    """Filter entity IDs to those the user can access for the given policy key."""
    if user.is_admin or user.permissions.access_all_entities(key):
        return list(entity_ids)
    check_entity = user.permissions.check_entity
    return [entity_id for entity_id in entity_ids if check_entity(entity_id, key)]


class AbstractPermissions:
    """Default permissions class."""

    _cached_entity_func: Callable[[str, str], bool] | None = None

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        raise NotImplementedError

    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        raise NotImplementedError

    def check_entity(self, entity_id: str, key: str) -> bool:
        """Check if we can access entity."""
        if (entity_func := self._cached_entity_func) is None:
            entity_func = self._cached_entity_func = self._entity_func()

        return entity_func(entity_id, key)


class PolicyPermissions(AbstractPermissions):
    """Handle permissions."""

    def __init__(self, policy: PolicyType, perm_lookup: PermissionLookup) -> None:
        """Initialize the permission class."""
        self._policy = policy
        self._perm_lookup = perm_lookup

    @override
    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        return test_all(self._policy.get(CAT_ENTITIES), key)

    @override
    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        return compile_entities(self._policy.get(CAT_ENTITIES), self._perm_lookup)

    @override
    def __eq__(self, other: object) -> bool:
        """Equals check."""
        return isinstance(other, PolicyPermissions) and other._policy == self._policy


class _OwnerPermissions(AbstractPermissions):
    """Owner permissions."""

    @override
    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        return True

    @override
    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        return lambda entity_id, key: True


OwnerPermissions = _OwnerPermissions()


# RBAC
async def async_setup_rbac(hass: HomeAssistant) -> None:
    """Set up the RBAC subsystem."""
    # this parser initialize with config/rbac.json. If needs to change file path change this here
    policy = RBACPolicyParser(Path(hass.config.path("rbac.json")))

    policy.load()

    chain = RBACChain(policy=policy)

    hass.data[ACCESS_CONTROL_DOMAIN] = {"policy": policy, "chain": chain}


async def async_authorize(
    hass: HomeAssistant, connection: ActiveConnection, msg: dict[str, Any]
) -> bool:
    """Authorize a WebSocket service call."""
    context = RBACContext(
        hass=hass,
        connection=connection,
        user=connection.user,
        message=msg,
    )

    chain: RBACChain = hass.data[ACCESS_CONTROL_DOMAIN]["chain"]

    return chain.handle(context)


def sync_authorize(
    hass: HomeAssistant, connection: ActiveConnection, msg: dict[str, Any]
) -> bool:
    """Authorize a WebSocket service call."""
    context = RBACContext(
        hass=hass,
        connection=connection,
        user=connection.user,
        message=msg,
    )

    chain: RBACChain = hass.data[ACCESS_CONTROL_DOMAIN]["chain"]

    return chain.handle(context)
