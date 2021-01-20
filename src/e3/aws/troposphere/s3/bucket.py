"""Provide S3 buckets."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Dict, List

from troposphere import AWSObject, s3

from e3.aws import Construct, name_to_id
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.s3.policy_statement import (
    DenyUnsecureTransport,
    DenyBadEncryptionHeader,
    DenyUnencryptedObjectUploads,
    AWSConfigBucketPermissionsCheck,
    AWSConfigBucketDelivery,
)


@dataclass(frozen=True)
class Bucket(Construct):
    """Define a S3 bucket construct with security parameters and a security policy.

    :param name: bucket name
    :param enable_versioning: can be set to enable multiple versions of all
         objects in the bucket.
    """

    name: str
    enable_versioning: bool = True
    bucket_encryption: Dict[str, List[Dict[str, Dict[str, str]]]] = field(
        default_factory=lambda: {
            "ServerSideEncryptionConfiguration": [
                {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
        init=False,
    )
    public_access_block_configuration: s3.PublicAccessBlockConfiguration = field(
        default_factory=lambda: s3.PublicAccessBlockConfiguration(
            "DefaultPublicAccessBlockConfiguration",
            BlockPublicAcls=True,
            BlockPublicPolicy=True,
            IgnorePublicAcls=True,
            RestrictPublicBuckets=True,
        ),
        init=False,
    )

    @property
    def policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the bucket."""
        return PolicyDocument(
            statements=[
                DenyUnsecureTransport(bucket=self.name),
                DenyBadEncryptionHeader(bucket=self.name),
                DenyUnencryptedObjectUploads(bucket=self.name),
            ]
        )

    @property
    def resources(self) -> List[AWSObject]:
        """Construct and return a s3.Bucket and its associated s3.BucketPolicy."""
        versioning_status = "Suspended"
        if self.enable_versioning:
            versioning_status = "Enabled"

        return [
            s3.Bucket(
                name_to_id(self.name),
                BucketName=self.name,
                BucketEncryption=s3.BucketEncryption.from_dict(
                    "DefautBucketEncryption", self.bucket_encryption
                ),
                PublicAccessBlockConfiguration=self.public_access_block_configuration,
                VersioningConfiguration=s3.VersioningConfiguration(
                    Status=versioning_status
                ),
            ),
            s3.BucketPolicy(
                name_to_id(self.name) + "Policy",
                Bucket=self.name,
                PolicyDocument=self.policy_document.as_dict,
                DependsOn=name_to_id(self.name),
            ),
        ]


@dataclass(frozen=True)
class AWSConfigBucket(Bucket):
    """Define a bucket to be used by a AWS Config DeliveryChannel.

    :param name: bucket name
    """

    name: str

    @property
    def policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the bucket."""
        return super().policy_document + PolicyDocument(
            statements=[
                AWSConfigBucketPermissionsCheck(bucket=self.name),
                AWSConfigBucketDelivery(bucket=self.name),
            ]
        )
