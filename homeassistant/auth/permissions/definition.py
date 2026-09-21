"""RBAC Handler frontend request definition."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RBACHandlerFrontRequestDefinition:
    """RBAC handler frontend request definition class."""

    id: str
    label: str
    type: str
    attribute: str
