"""Provide IAM Role classes."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from troposphere import AWSObject, iam, Tags, GetAtt

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import (
    AssumeRole,
    Trust,
    Allow,
    PolicyStatement,
)

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack
    from e3.aws.troposphere.iam.policy_statement import PrincipalType


@dataclass
class Role(Construct):
    """Define IAM role with an attached assume_role policy document.

    :param name: role name
    :param description: role description
    :param trust: trust policy. It can be either a principal, a Trust statement or
        a policy document
    :param managed_policy_arns: list of ARNs of IAM managed policies to attach
        to the role
    :param max_session_duration: the maximum session duration (in seconds) that
        you want to set for the specified role. default is one hour
    :param tags: a list of tags that are attached to the specified role
    :param path: The path to the role.
    :param boundary: The ARN of the policy used to set the permissions boundary
        for the role.
    :param condition: condition contains statements that define the circumstances
        under which role the is created.
    :param inline_policies: a dict of inline policy documents that are embedded in
        the role, the keys are the names of the policies and the values are the
        policy documents. They can be added or updated
    """

    name: str
    description: str
    trust: PrincipalType | Trust | PolicyDocument
    managed_policy_arns: list[str] | None = None
    max_session_duration: int | None = None
    tags: dict[str, str] = field(default_factory=lambda: {})
    path: str = "/"
    boundary: str | None = None
    condition: dict[str, dict] | None = None
    inline_policies: dict[str, PolicyDocument | PolicyStatement | dict] | None = None

    @property
    def trust_policy(self) -> PolicyDocument:
        """Return the trust policy for the role."""
        if isinstance(self.trust, Trust):
            return PolicyDocument(statements=[self.trust])
        elif isinstance(self.trust, PolicyDocument):
            return self.trust
        else:
            return PolicyDocument(statements=[AssumeRole(principal=self.trust)])

    @property
    def policies(self) -> list[iam.Policy] | None:
        """Return inline policies."""
        if not self.inline_policies:
            return None

        policies = []
        for policy_name, policy_document in self.inline_policies.items():
            args: dict[str, str | dict | PolicyStatement | PolicyDocument] = {}
            args["PolicyName"] = policy_name
            if isinstance(policy_document, dict):
                args["PolicyDocument"] = policy_document

            elif isinstance(policy_document, PolicyDocument):
                args["PolicyDocument"] = policy_document.as_dict

            elif isinstance(policy_document, PolicyStatement):
                args["PolicyDocument"] = PolicyDocument(
                    statements=[policy_document]
                ).as_dict

            policies.append(iam.Policy(**args))
        return policies

    @property
    def arn(self):
        return GetAtt(name_to_id(self.name), "Arn")

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return troposphere objects defining the role."""
        attr = {}

        for key, val in {
            "RoleName": self.name,
            "Description": self.description,
            "ManagedPolicyArns": self.managed_policy_arns,
            "MaxSessionDuration": self.max_session_duration,
            "AssumeRolePolicyDocument": self.trust_policy.as_dict,
            "Tags": Tags({"Name": self.name, **self.tags}),
            "Path": self.path,
            "PermissionsBoundary": self.boundary,
            "Condition": self.condition,
            "Policies": self.policies,
        }.items():
            if val is not None:
                attr[key] = val

        return [iam.Role(name_to_id(self.name), **attr)]

    def cfn_policy_document(self, stack: Stack) -> PolicyDocument:
        return PolicyDocument(
            statements=[
                Allow(
                    action=[
                        "iam:GetRole",
                        "iam:CreateRole",
                        "iam:AttachRolePolicy",
                        "iam:DetachRolePolicy",
                        "iam:DeleteRole",
                    ],
                    resource=f"arn:aws:iam::%(account)s:role/{self.name}",
                )
            ]
        )
