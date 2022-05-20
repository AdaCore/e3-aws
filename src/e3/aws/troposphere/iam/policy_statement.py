"""Provide PolicyStatement class."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional, Union, Dict, List

    PrincipalType = Union[str, Dict[str, Union[str, List[str]]]]
    ConditionType = Dict[str, Dict[str, Union[str, List[str]]]]


class PolicyStatement:
    """Default Policy statement class."""

    def __init__(
        self,
        action: str | list[str],
        effect: str = "Deny",
        resource: Optional[str] = None,
        principal: Optional[PrincipalType] = None,
        condition: Optional[ConditionType] = None,
    ) -> None:
        """Initialize a policy statement.

        :param action: actions on which the policy has effect
        :param effect: effect of the policy (Allow, Deny ..)
        :param resource: resource on which the policy has effect
        :param principal: principal affected by the policy
        :param condition: conditions for when the policy is in effect
        """
        self.action = action
        self.effect = effect
        self.resource = resource
        self.principal = principal
        self.condition = condition

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


class Allow(PolicyStatement):
    def __init__(
        self,
        action: str | list[str],
        resource: Optional[str] = None,
        principal: Optional[PrincipalType] = None,
        condition: Optional[ConditionType] = None,
    ) -> None:
        """Initialize an Allow policy statement.

        :param action: actions on which the policy has effect
        :param resource: resource on which the policy has effect
        :param principal: principal affected by the policy
        :param condition: conditions for when the policy is in effect
        """
        return super().__init__(
            action=action,
            effect="Allow",
            resource=resource,
            principal=principal,
            condition=condition,
        )


class AssumeRole(PolicyStatement):
    """Define a sts:AssumeRole role policy statement."""

    def __init__(
        self, principal: PrincipalType, condition: Optional[ConditionType] = None
    ):
        """Initialize an AssumeRole statement.

        :param principal: principal which are allowed to assume the role
        :param condition: condition to apply
        """
        super().__init__(
            action="sts:AssumeRole",
            effect="Allow",
            resource=None,
            principal=principal,
            condition=condition,
        )


class Trust(PolicyStatement):
    """Policy statement used in trust policies."""

    def __init__(
        self,
        services: Optional[list[str]] = None,
        accounts: Optional[list[str]] = None,
        users: Optional[list[tuple[str, str]]] = None,
        condition: Optional[ConditionType] = None,
        actions: list[str] | str = "sts:AssumeRole",
    ) -> None:
        """Initialize a trust policy statement.

        :param services: list of services to trust (without amazonaws.com suffix)
        :param accounts: list of accounts to trust (accounts alias not allowed)
        :param users: list of users as tuple (account number, user name)
        :param condition: condition to apply to the statement
        :param actions: list of trusted actions. If None, the action iam:AssumeRole
            is used.
        """
        self.principals: dict[str, list[str]] = {}

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
        self.actions = actions

    @property
    def as_dict(self) -> dict[str, Any]:
        """See PolicyStatement doc."""
        result: dict[str, str | list[str] | dict[str, list[str]] | ConditionType] = {
            "Effect": "Allow",
            "Action": self.actions,
            "Principal": self.principals,
        }

        if self.condition is not None:
            result["Condition"] = self.condition

        return result
