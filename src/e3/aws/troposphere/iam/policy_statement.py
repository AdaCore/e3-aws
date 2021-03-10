"""Provide PolicyStatement class."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional

    PrincipalType = str | dict[str, str | list[str]]
    ConditionType = dict[str, dict[str, str | list[str]]]


@dataclass
class PolicyStatement:
    """Default Policy statement class.

    :param action: actions on which the policy has effect
    :param effect: effect of the policy (Allow, Deny ..)
    :param resource: resource on which the policy has effect
    :param principal: principal affected by the policy
    :param condition: conditions for when the policy is in effect
    """

    action: str | list[str]
    effect: str = "Deny"
    resource: Optional[str] = None
    principal: Optional[PrincipalType] = None
    condition: Optional[ConditionType] = None

    @property
    def as_dict(self) -> dict[str, Any]:
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


@dataclass
class AssumeRole(PolicyStatement):
    """Define a sts:AssumeRole role policy statement.

    :param principal: principal which are allowed to assume the role
    """

    principal: PrincipalType = field(default_factory=lambda: {"AWS": "*"})
    action: str = field(default="sts:AssumeRole", init=False)
    effect: str = field(default="Allow", init=False)


class Trust(PolicyStatement):
    """Policy statement used in trust policies."""

    def __init__(
        self,
        services: Optional[list[str]] = None,
        accounts: Optional[list[str]] = None,
        users: Optional[list[tuple(str, str)]] = None,
        condition: Optional[ConditionType] = None,
    ) -> None:
        """Initialize a trust policy statement.

        :param services: list of services to trust (without amazonaws.com suffix)
        :param accounts: list of accounts to trust (accounts alias not allowed)
        :param users: list of users as tuple (account number, user name)
        :param condition: condition to apply to the statement
        """
        self.principals = {}

        if services is not None:
            self.principals.setdefault("Service", [])
            self.principals["Service"] += [
                f"{service}.amazonaws.com" for service in services
            ]

        if accounts is not None:
            self.principals.setdefault("AWS", [])
            self.principals["AWS"] += [
                f"arn:aws:iam::{account}:root" for account in accounts
            ]

        if users is not None:
            self.principals.setdefault("AWS", [])
            self.principals["AWS"] += [
                f"arn:aws:iam::{account}:user/{user}" for account, user in users
            ]

        self.condition = condition

    @property
    def as_dict(self) -> dict[str, Any]:
        """See PolicyStatement doc."""
        result = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": self.principals,
        }

        if self.condition is not None:
            result["Condition"] = self.condition

        return result
