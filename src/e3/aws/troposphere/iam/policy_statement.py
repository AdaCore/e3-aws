"""Provide PolicyStatement class."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ResourceType = str | list[str]
    PrincipalType = str | dict[str, str | list[str]]
    ConditionType = str | dict[str, dict[str, str | list[str]]]


class PolicyStatement:
    """Default Policy statement class."""

    def __init__(
        self,
        action: str | list[str],
        sid: str | None = None,
        effect: str = "Deny",
        resource: ResourceType | None = None,
        principal: PrincipalType | None = None,
        condition: ConditionType | None = None,
    ) -> None:
        """Initialize a policy statement.

        :param action: actions on which the policy has effect
        :param sid: unique statement identifier
        :param effect: effect of the policy (Allow, Deny ...)
        :param resource: resource on which the policy has effect
        :param principal: principal affected by the policy
        :param condition: conditions for when the policy is in effect
        """
        self.sid = sid
        self.action = action
        self.effect = effect
        self.resource = resource
        self.principal = principal
        self.condition = condition

    @property
    def as_dict(self) -> dict[str, Any]:
        """Return a dictionary defining a troposphere policy statement."""
        return {
            key: val
            for key, val in {
                "Sid": self.sid,
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
        sid: str | None = None,
        resource: ResourceType | None = None,
        principal: PrincipalType | None = None,
        condition: ConditionType | None = None,
    ) -> None:
        """Initialize an Allow policy statement.

        :param action: actions on which the policy has effect
        :param sid: unique statement identifier
        :param resource: resource on which the policy has effect
        :param principal: principal affected by the policy
        :param condition: conditions for when the policy is in effect
        """
        super().__init__(
            sid=sid,
            action=action,
            effect="Allow",
            resource=resource,
            principal=principal,
            condition=condition,
        )


class AssumeRole(PolicyStatement):
    """Define a sts:AssumeRole role policy statement."""

    def __init__(
        self,
        principal: PrincipalType,
        sid: str | None = None,
        condition: ConditionType | None = None,
    ):
        """Initialize an AssumeRole statement.

        :param principal: principal which are allowed to assume the role
        :param sid: unique statement identifier
        :param condition: condition to apply
        """
        super().__init__(
            sid=sid,
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
        sid: str | None = None,
        services: list[str] | None = None,
        accounts: list[str] | None = None,
        users: list[tuple[str, str]] | None = None,
        roles: list[tuple[str, str]] | None = None,
        condition: ConditionType | None = None,
        actions: list[str] | str = "sts:AssumeRole",
    ) -> None:
        """Initialize a trust policy statement.

        :param sid: unique statement identifier
        :param services: list of services to trust (without amazonaws.com suffix)
        :param accounts: list of accounts to trust (accounts alias not allowed)
        :param users: list of users as tuple (account number, user name)
        :param roles: list of roles as tuple (account number, role name)
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

        if roles is not None:
            self.principals.setdefault("AWS", [])
            self.principals["AWS"] += [
                f"arn:aws:iam::{account}:role/{role}" for account, role in roles
            ]

        self.condition = condition
        self.actions = actions
        self.sid = sid

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

        if self.sid is not None:
            result["Sid"] = self.sid

        return result
