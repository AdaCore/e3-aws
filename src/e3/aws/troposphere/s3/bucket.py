"""Provide S3 buckets."""

from __future__ import annotations
from typing import TYPE_CHECKING


from troposphere import AWSObject, s3, Ref

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement


if TYPE_CHECKING:
    from typing import Optional
    from e3.aws.troposphere import Stack


class Bucket(Construct):
    """Define a S3 bucket construct with security parameters and a security policy."""

    def __init__(
        self,
        name: str,
        enable_versioning: bool = True,
        lifecycle_rules: Optional[list[s3.LifecycleRule]] = None,
    ):
        """Initialize a bucket.

        :param name: bucket name
        :param enable_versioning: can be set to enable multiple versions of all
            objects in the bucket.
        :param lifecycle_rules: lifecycle rules for bucket objects
        """
        self.name = name
        self.enable_versioning = enable_versioning
        self.lifecycle_rules = lifecycle_rules

        # Add minimal policy statements
        self.policy_statements = [
            # Deny any request not using https transport protocol
            PolicyStatement(
                action="s3:*",
                effect="Deny",
                resource=self.all_objects_arn,
                principal={"AWS": "*"},
                condition={"Bool": {"aws:SecureTransport": "false"}},
            ),
            # Deny to store object not encrypted with AES256 encryption
            PolicyStatement(
                action="s3:PutObject",
                effect="Deny",
                resource=self.all_objects_arn,
                principal={"AWS": "*"},
                condition={
                    "StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}
                },
            ),
            # Deny to store non encrypted objects
            # (??? do we really need that statement)
            PolicyStatement(
                action="s3:PutObject",
                effect="Deny",
                resource=self.all_objects_arn,
                principal={"AWS": "*"},
                condition={"Null": {"s3:x-amz-server-side-encryption": "true"}},
            ),
        ]

        self.bucket_encryption = {
            "ServerSideEncryptionConfiguration": [
                {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        }

    @property
    def policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the bucket."""
        return PolicyDocument(statements=self.policy_statements)

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Construct and return a s3.Bucket and its associated s3.BucketPolicy."""
        # Handle versioning configuration
        versioning_status = "Suspended"
        if self.enable_versioning:
            versioning_status = "Enabled"

        # Block all public accesses
        public_access_block_config = s3.PublicAccessBlockConfiguration(
            BlockPublicAcls=True,
            BlockPublicPolicy=True,
            IgnorePublicAcls=True,
            RestrictPublicBuckets=True,
        )

        # Set default bucket encryption to AES256
        bucket_encryption = s3.BucketEncryption(
            ServerSideEncryptionConfiguration=[
                s3.ServerSideEncryptionRule(
                    ServerSideEncryptionByDefault=s3.ServerSideEncryptionByDefault(
                        SSEAlgorithm="AES256"
                    )
                )
            ]
        )

        lifecycle_config = None
        if self.lifecycle_rules:
            lifecycle_config = s3.LifecycleConfiguration(
                name_to_id(self.name) + "LifeCycleConfig", Rules=self.lifecycle_rules
            )

        attr = {}
        for key, val in {
            "BucketName": self.name,
            "BucketEncryption": bucket_encryption,
            "PublicAccessBlockConfiguration": public_access_block_config,
            "VersioningConfiguration": s3.VersioningConfiguration(
                Status=versioning_status
            ),
            "LifecycleConfiguration": lifecycle_config,
        }.items():
            if val is not None:
                attr[key] = val

        return [
            s3.Bucket(name_to_id(self.name), **attr),
            s3.BucketPolicy(
                name_to_id(self.name) + "Policy",
                Bucket=self.ref,
                PolicyDocument=self.policy_document.as_dict,
            ),
        ]

    @property
    def ref(self):
        return Ref(name_to_id(self.name))

    @property
    def arn(self):
        return f"arn:aws:s3:::{self.name}"

    @property
    def all_objects_arn(self):
        return f"{self.arn}/*"

    def cfn_policy_document(self, stack: Stack) -> PolicyDocument:
        return PolicyDocument(
            [
                PolicyStatement(
                    action=[
                        "s3:CreateBucket",
                        "s3:DeleteBucket",
                        "s3:DeleteBucketPolicy",
                        "s3:GetBucketPolicy",
                        "s3:PutBucketPolicy",
                        "s3:PutEncryptionConfiguration",
                        "s3:GetEncryptionConfiguration",
                        "s3:PutBucketVersioning",
                        "s3:GetBucketVersioning",
                        "s3:PutBucketPublicAccessBlock",
                        "s3:GetBucketPublicAccessBlock",
                    ],
                    effect="Allow",
                    resource=self.arn,
                )
            ]
        )
