"""Provide IAM Managed policies."""
from __future__ import annotations
from typing import TYPE_CHECKING
from troposphere import iam, AWSObject, Ref

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement, Allow

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack


class ManagedPolicy(Construct):
    """AWS ManagedPolicy."""

    def __init__(
        self, name: str, statements: list[PolicyStatement], description: str = ""
    ) -> None:
        """Initialize an IAM Managed policy.

        :param name: name of the managed policy
        :param description: managed_policy description
        :param statements: policy statement part of the policy
        """
        self.name = name
        self.description = description
        self.statements = statements

    @property
    def arn(self) -> Ref:
        """Return managed policy arn."""
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return troposphere objects defining the managed policy."""
        params = {
            "Description": self.description,
            "ManagedPolicyName": self.name,
            "PolicyDocument": PolicyDocument(statements=self.statements).as_dict,
        }
        return [iam.ManagedPolicy(name_to_id(self.name), **params)]

    def cfn_policy_document(self, stack: Stack) -> PolicyDocument:
        return PolicyDocument(
            statements=[
                Allow(
                    action=[
                        "iam:GetPolicy",
                        "iam:CreatePolicy",
                        "iam:ListPolicyVersions",
                        "iam:DeletePolicy",
                        "iam:CreatePolicyVersion",
                        "iam:DeletePolicyVersion",
                    ],
                    resource=f"arn:aws:iam::%(account)s:policy/{self.name}",
                )
            ]
        )
