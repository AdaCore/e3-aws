"""Provide s3 high level constructs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.managed_policy import ManagedPolicy

from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import (
    Allow,
    Trust,
    AssumeRole,
    PolicyStatement,
)
from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere.s3.bucket import Bucket

if TYPE_CHECKING:
    from typing import Any
    from troposphere import AWSObject, Stack
    from e3.aws.troposphere.iam.policy_statement import PrincipalType


class BucketWithRoles(Construct):
    """Provide resources for a s3 bucket with its access roles."""

    def __init__(
        self,
        name: str,
        iam_names_prefix: str,
        iam_path: str,
        trusted_accounts: list[str] | None = None,
        trust_policy: (
            PrincipalType
            | list[PolicyStatement]
            | PolicyStatement
            | PolicyDocument
            | None
        ) = None,
        iam_read_root_name: str = "Read",
        iam_write_root_name: str = "Write",
        bucket_exists: bool | None = None,
        read_trusted_accounts: list[str] | None = None,
        write_trusted_accounts: list[str] | None = None,
        read_trust_policy: (
            PrincipalType
            | list[PolicyStatement]
            | PolicyStatement
            | PolicyDocument
            | None
        ) = None,
        write_trust_policy: (
            PrincipalType
            | list[PolicyStatement]
            | PolicyStatement
            | PolicyDocument
            | None
        ) = None,
        **bucket_kwargs: Any,
    ) -> None:
        """Initialize BucketWithRoles instance.

        :param name: name of the bucket
        :param iam_names_prefix: prefix for policies and roles names
        :param iam_path: path for iam resources
        :param trusted_accounts: accounts to be trusted by access roles
        :param trust_policy: custom trust policy for access roles. It can be
            either a principal, a list of statement or a policy document.
        :param iam_read_root_name: root name for read access roles and policy
        :param iam_write_root_name: root name for write access roles and policy
        :param bucket_exists: if True then the bucket is not created
        :param read_trusted_accounts: additional trusted accounts for read access
        :param write_trusted_accounts: additional trusted accounts for write access
        :param read_trust_policy: additional custom trust policy for read access.
            It can be either a principal, a list of statements or a policy document.
        :param write_trust_policy: additional custom trust policy for write access.
            It can be either a principal, a list of statements or a policy document.
        :param bucket_kwargs: keyword arguments to pass to the bucket constructor
        """
        # check that only the accounts or the policy parameter are
        # set not both
        for el in [
            {
                f"{trust_policy=}".split("=")[0]: trust_policy,
                f"{trusted_accounts=}".split("=")[0]: trusted_accounts,
            },
            {
                f"{read_trust_policy=}".split("=")[0]: read_trust_policy,
                f"{read_trusted_accounts=}".split("=")[0]: read_trusted_accounts,
            },
            {
                f"{write_trust_policy=}".split("=")[0]: write_trust_policy,
                f"{write_trusted_accounts=}".split("=")[0]: write_trusted_accounts,
            },
        ]:
            if all(el.values()):
                keys = list(el.keys())
                raise AttributeError(
                    f"You cannot set {keys[0]!r} and {keys[1]!r} at the"
                    " same time , please use one or the other."
                )
        self.name = name
        self.iam_names_prefix = iam_names_prefix
        self.trusted_accounts = trusted_accounts if trusted_accounts is not None else []
        self.read_trusted_accounts = (
            read_trusted_accounts if read_trusted_accounts is not None else []
        )
        self.write_trusted_accounts = (
            write_trusted_accounts if write_trusted_accounts is not None else []
        )
        self.bucket_exists = bucket_exists

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

        self.read_trust_policy = PolicyDocument(statements=[])
        self.write_trust_policy = PolicyDocument(statements=[])

        if self.trusted_accounts or self.read_trusted_accounts:
            self.read_trust_policy += PolicyDocument(
                statements=[
                    Trust(accounts=self.trusted_accounts + self.read_trusted_accounts)
                ]
            )
        if self.trusted_accounts or self.write_trusted_accounts:
            self.write_trust_policy += PolicyDocument(
                statements=[
                    Trust(accounts=self.trusted_accounts + self.write_trusted_accounts)
                ]
            )

        for policy_type, policy in [
            (None, trust_policy),
            ("read", read_trust_policy),
            ("write", write_trust_policy),
        ]:
            if not policy:
                continue

            if isinstance(policy, list):
                policy_document = PolicyDocument(statements=policy)
            elif isinstance(policy, PolicyStatement):
                policy_document = PolicyDocument(statements=[policy])
            elif isinstance(policy, PolicyDocument):
                policy_document = policy
            else:
                policy_document = PolicyDocument(
                    statements=[AssumeRole(principal=policy)]
                )

            if policy_type in ("read", None):
                self.read_trust_policy += policy_document

            if policy_type in ("write", None):
                self.write_trust_policy += policy_document

        self.read_role = Role(
            name=f"{self.iam_names_prefix}{iam_read_root_name}Role",
            description=f"Role with read access to {self.name} bucket.",
            trust=self.read_trust_policy,
            managed_policy_arns=[self.read_policy.arn],
            path=iam_path,
        )

        self.push_role = Role(
            name=f"{self.iam_names_prefix}{iam_write_root_name}Role",
            description=f"Role with read and write access to {self.name} bucket.",
            trust=self.write_trust_policy,
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

    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
        """Return resources associated with the construct."""
        return ([] if self.bucket_exists else [self.bucket]) + [
            self.read_policy,
            self.read_role,
            self.push_policy,
            self.push_role,
        ]
