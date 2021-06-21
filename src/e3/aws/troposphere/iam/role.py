"""Provide IAM Role classes."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from troposphere import AWSObject, iam, Tags, GetAtt

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import AssumeRole, Trust, Allow

if TYPE_CHECKING:
    from typing import Optional
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
    """

    name: str
    description: str
    trust: PrincipalType | Trust | PolicyDocument
    managed_policy_arns: Optional[list[str]] = None
    max_session_duration: Optional[int] = None
    tags: dict[str, str] = field(default_factory=lambda: {})
    path: str = "/"
    boundary: Optional[str] = None

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
