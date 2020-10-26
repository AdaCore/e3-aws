"""Provide IAM Role classes."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List
    from e3.aws.troposphere.iam.policy_document import PrincipalType

from troposphere import iam, AWSObject

from e3.aws import Construct, name_to_id
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import AssumeRole


@dataclass(frozen=True)
class Role(Construct):
    """Define IAM role with an attached assume_role policy document.

    :param name: role name
    :param description: role description
    :param principal: principal which are allowed to assume this role
    :param managed_policy_arns: list of ARNs of IAM managed policies to attach
        to the role
    """

    name: str
    description: str
    principal: PrincipalType
    managed_policy_arns: List[str] = field(default_factory=list)

    _assume_role_policy_document: PolicyDocument = field(
        default=PolicyDocument([]), init=False
    )

    @property
    def assume_role_policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the bucket."""
        return PolicyDocument(statements=[AssumeRole(principal=self.principal)])

    @property
    def aws_objects(self) -> List[AWSObject]:
        """Return troposphere objects defining the role."""
        attr = {
            "RoleName": self.name,
            "Description": self.description,
            "ManagedPolicyArns": self.managed_policy_arns,
            "AssumeRolePolicyDocument": self.assume_role_policy_document.as_dict,
        }
        return [iam.Role.from_dict(name_to_id(self.name), attr)]
