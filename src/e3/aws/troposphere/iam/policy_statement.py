"""Provide PolicyStatement class."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional, Union

    PrincipalType = Union[str, Dict[str, Union[str, List[str]]]]

from e3.aws.troposphere import Property


@dataclass(frozen=True)
class PolicyStatement(Property):
    """Default Policy statement class.

    :param action: actions on which the policy has effect
    :param effect: effect of the policy (Allow, Deny ..)
    :param resource: resource on which the policy has effect
    :param principal: principal affected by the policy
    :param condition: conditions for when the policy is in effect
    """

    action: List[str]
    effect: str = "Deny"
    resource: Optional[str] = None
    principal: PrincipalType = None
    condition: Optional[Dict[str, Dict[str, str]]] = None

    @property
    def as_dict(self) -> Dict[str, Any]:
        """Return a dictionnary defining a troposphere policy statement."""
        return {
            key: val
            for key, val in {
                "Effect": self.effect,
                "Principal": self.principal,
                "Action": self.action,
                "Resource": self.resource,
                "Condition": self.condition,
            }.items()
            if val is not None
        }


@dataclass(frozen=True)
class AssumeRole(PolicyStatement):
    """Define a sts:AssumeRole role policy statement.

    :param principal: principal which are allowed to assume the role
    """

    principal: PrincipalType = field(default_factory=lambda: {"AWS": "*"})
    action: str = field(default="sts:AssumeRole", init=False)
    effect: str = field(default="Allow", init=False)
