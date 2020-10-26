"""Provide policy statements that could be used to define a bucket policy."""
from __future__ import annotations
from dataclasses import dataclass, field
from itertools import chain
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Dict, List, Optional
    from e3.aws.troposphere.iam.policy_statement import PrincipalType

from troposphere import AccountId, Join


from e3.aws.troposphere.iam.policy_statement import PolicyStatement


@dataclass(frozen=True)
class AWSConfigAllow(PolicyStatement):
    """Define a default s3 policy statement class for AWSConfig delivery bucket.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    action: str = field(default="s3:*", init=False)
    effect: str = field(default="Allow", init=False)
    principal: PrincipalType = field(
        default_factory=lambda: {"Service": "config.amazonaws.com"}, init=False
    )

    @property
    def resource(self) -> str:
        """Return resource attribute."""
        return f"arn:aws:s3:::{self.bucket}"

    @resource.setter
    def resource(self, value: str) -> None:
        """Setter needed for dataclass to build constructor."""
        return


@dataclass(frozen=True)
class AWSConfigBucketPermissionsCheck(AWSConfigAllow):
    """Define AWSConfigBucketPermissionsCheck policy statement.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    action: str = field(default="s3:GetBucketAcl", init=False)


@dataclass(frozen=True)
class AWSConfigBucketExistenceCheck(AWSConfigAllow):
    """Define AWSConfigBucketExistenceCheck policy statement.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    action: str = field(default="s3:ListBucket", init=False)


@dataclass(frozen=True)
class AWSConfigBucketDelivery(AWSConfigAllow):
    """Define AWSConfigBucketDelivery policy statement.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    action: str = field(default="s3:PutObject", init=False)
    condition: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {
            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
        },
        init=False,
    )

    @property
    def resource(self) -> str:
        """Return resource attribute."""
        return Join(
            "", ["arn:aws:s3:::", self.bucket, "/AWSLogs/", AccountId, "/Config/*"]
        )

    @resource.setter
    def resource(self, value: str) -> None:
        """Setter needed for dataclass to build constructor."""
        return


@dataclass(frozen=True)
class S3DenyAll(PolicyStatement):
    """Define a default s3 policy statement class.

    Defaults are set to deny all actions from any principals to any objects.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    action: str = field(default="s3:*", init=False)
    effect: str = field(default="Deny", init=False)
    principal: PrincipalType = field(default_factory=lambda: {"AWS": "*"}, init=False)

    @property
    def resource(self) -> None:
        """Return resource attribute."""
        return f"arn:aws:s3:::{self.bucket}/*"

    @resource.setter
    def resource(self, value: str) -> None:
        """Setter needed for dataclass to build constructor."""
        return


@dataclass(frozen=True)
class DenyUnsecureTransport(S3DenyAll):
    """Define a S3 policy statement fields to deny unsecure transport.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    condition: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {"Bool": {"aws:SecureTransport": "false"}}, init=False
    )


@dataclass(frozen=True)
class DenyBadEncryptionHeader(S3DenyAll):
    """Define a S3 policy statement fields to deny bad encryption header.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    action: str = field(default="s3:PutObject", init=False)
    condition: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {
            "StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}
        },
        init=False,
    )


@dataclass(frozen=True)
class DenyUnencryptedObjectUploads(S3DenyAll):
    """Define a S3 policy statement fields to deny unencrypted object uploads.

    :param bucket: name of the bucket affected by the policy statement
    """

    bucket: str = ""
    action: str = field(default="s3:PutObject", init=False)
    condition: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {"Null": {"s3:x-amz-server-side-encryption": "true"}},
        init=False,
    )


@dataclass(frozen=True)
class AllowAccess(PolicyStatement):
    """Define a S3 access policy statement.

    :param buckets: list of bucket to which acces must be given
    :param action: list of actions to allow
    """

    action: List[str] = field(default_factory=list)
    effect: str = field(default="Allow", init=False)
    buckets: List[str] = field(default_factory=list)
    _resource: Optional[str] = field(default=None, init=False)

    @property
    def resource(self) -> str:
        """Return arns from buckets and bucket objects."""
        return list(
            chain.from_iterable(
                ((f"arn:aws:s3:::{b}", f"arn:aws:s3:::{b}/*") for b in self.buckets)
            )
        )

    @resource.setter
    def resource(self, value: str) -> None:
        """Setter needed for dataclass to build constructor."""
        return
