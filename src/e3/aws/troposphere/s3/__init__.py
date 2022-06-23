"""Provide s3 high level constructs."""
from __future__ import annotations

from typing import TYPE_CHECKING

from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.managed_policy import ManagedPolicy
from e3.aws.troposphere.iam.policy_statement import Allow, Trust
from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere.s3.bucket import Bucket

if TYPE_CHECKING:
    from typing import Any, Union
    from troposphere import AWSObject, Stack


class BucketWithRoles(Construct):
    """Provide resources for a s3 bucket with its access roles."""

    def __init__(
        self,
        name: str,
        iam_names_prefix: str,
        iam_path: str,
        trusted_accounts: list[str],
        iam_read_root_name: str = "Read",
        iam_write_root_name: str = "Write",
        **bucket_kwargs: Any,
    ) -> None:
        """Initialize BucketWithRoles instance.

        :param name: name of the bucket
        :param iam_names_prefix: prefix for policies and roles names
        :param iam_path: path for iam resources
        :param trusted_accounts: accounts to be trusted by access roles
        :param iam_read_root_name: root name for read access roles and policy
        :param iam_write_root_name: root name for write access roles and policy
        :param bucket_kwargs: keyword arguments to pass to the bucket constructor
        """
        self.name = name
        self.iam_names_prefix = iam_names_prefix
        self.trusted_accounts = trusted_accounts

        self.bucket = Bucket(name=self.name, **bucket_kwargs)
        self.read_policy = ManagedPolicy(
            name=f"{self.iam_names_prefix}{iam_read_root_name}Policy",
            description=f"Grants read access permissions to {self.name} bucket",
            statements=[
                Allow(action=["s3:GetObject"], resource=self.bucket.all_objects_arn),
                Allow(action=["s3:ListBucket"], resource=self.bucket.arn),
            ],
            path=iam_path,
        )
        self.read_role = Role(
            name=f"{self.iam_names_prefix}{iam_read_root_name}Role",
            description=f"Role with read access to {self.name} bucket.",
            trust=Trust(accounts=self.trusted_accounts),
            managed_policy_arns=[self.read_policy.arn],
            path=iam_path,
        )
        self.push_policy = ManagedPolicy(
            name=f"{self.iam_names_prefix}{iam_write_root_name}Policy",
            description=f"Grants write access permissions to {self.name} bucket",
            statements=[
                Allow(
                    action=["s3:PutObject", "s3:DeleteObject"],
                    resource=self.bucket.all_objects_arn,
                )
            ],
            path=iam_path,
        )
        self.push_role = Role(
            name=f"{self.iam_names_prefix}{iam_write_root_name}Role",
            description=f"Role with read and write access to {self.name} bucket.",
            trust=Trust(accounts=self.trusted_accounts),
            managed_policy_arns=[self.push_policy.arn, self.read_policy.arn],
            path=iam_path,
        )

    @property
    def ref(self):
        """Return bucket ref."""
        return self.bucket.ref

    @property
    def arn(self):
        """Return bucket arn."""
        return self.bucket.arn

    @property
    def all_objects_arn(self):
        return self.bucket.all_objects_arn

    def resources(self, stack: Stack) -> list[Union[AWSObject, Construct]]:
        """Return resources associated with the construct."""
        return [
            self.bucket,
            self.read_policy,
            self.read_role,
            self.push_policy,
            self.push_role,
        ]
