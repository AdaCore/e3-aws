"""Provide IAM Role classes."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Dict, List, Optional
    from e3.aws.troposphere.iam.policy_document import PrincipalType

from troposphere import AWSObject, iam, Tags

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
    :param max_session_duration: the maximum session duration (in seconds) that
        you want to set for the specified role. default is one hour
    :param tags: a list of tags that are attached to the specified role
    """

    name: str
    description: str
    principal: PrincipalType
    managed_policy_arns: Optional[List[str]] = None
    max_session_duration: Optional[int] = None
    tags: Dict[str, str] = field(default_factory=lambda: {})

    _assume_role_policy_document: PolicyDocument = field(
        default=PolicyDocument([]), init=False
    )

    @property
    def assume_role_policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the bucket."""
        return PolicyDocument(statements=[AssumeRole(principal=self.principal)])

    @property
    def resources(self) -> List[AWSObject]:
        """Return troposphere objects defining the role."""
        attr = {}

        for key, val in {
            "RoleName": self.name,
            "Description": self.description,
            "ManagedPolicyArns": self.managed_policy_arns,
            "MaxSessionDuration": self.max_session_duration,
            "AssumeRolePolicyDocument": self.assume_role_policy_document.as_dict,
            "Tags": Tags({"Name": self.name, **self.tags}),
        }.items():
            if val is not None:
                attr[key] = val

        return [iam.Role(name_to_id(self.name), **attr)]
