"""Provide IAM Managed policies."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING


from e3.aws.troposphere.iam.managed_policy import ManagedPolicy
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.s3.policy_statement import AllowAccess

if TYPE_CHECKING:
    from typing import List, Optional


@dataclass(frozen=True)
class S3AccessManagedPolicy(ManagedPolicy):
    """Define a S3 access managed policy.

    :param name: name of the policy
    :param description: managed_policy description
    :param buckets: list of buckets to which access is given
    :param action: list of actions
    :param users: names (friendly names, not ARN) of users to attach the policy to
    :param groups: names (friendly names, not ARN) of groups to attach the policy to
    :param roles: names (friendly names, not ARN) of roles to attach the policy to
    """

    name: str
    buckets: List[str] = field(default_factory=list)
    action: List[str] = field(default_factory=list)
    users: Optional[List[str]] = None
    groups: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    description: str = "S3 Bucket access managed policy"

    @property
    def policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the managed policy."""
        return PolicyDocument(
            statements=[AllowAccess(buckets=self.buckets, action=self.action)]
        )
