from __future__ import annotations
from typing import TYPE_CHECKING
from enum import Enum

from e3.aws.cfn import AWSType, Resource
from e3.aws.cfn.iam import PolicyDocument

if TYPE_CHECKING:
    from typing import Any

    from e3.aws.cfn import GetAtt


class AccessControl(Enum):
    """Canned ACLs for buckets."""

    AUTHENTICATED_READ = "AuthenticatedRead"
    AWS_EXEC_READ = "AwsExecRead"
    BUCKET_OWNER_READ = "BucketOwnerRead"
    BUCKET_OWNER_FULL_CONTROL = "BucketOwnerFullControl"
    LOG_DELIVERY_WRITE = "LogDeliveryWrite"
    PRIVATE = "Private"
    PUBLIC_READ = "PublicRead"
    PUBLIC_WRITE = "PublicReadWrite"


class BucketPolicy(Resource):
    """S3 Bucket Policy."""

    def __init__(
        self, name: str, bucket: Bucket | str, policy_document: PolicyDocument
    ) -> None:
        """Initialize a bucket policy.

        :param name: logical name of the resource in the stack
        :param bucket: bucket on which to apply the policy
        :param policy_document: Policy document to apply
        """
        super(BucketPolicy, self).__init__(name, kind=AWSType.S3_BUCKET_POLICY)
        self.bucket = bucket
        self.policy_document = policy_document

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {"PolicyDocument": self.policy_document.properties}
        if isinstance(self.bucket, Bucket):
            result["Bucket"] = self.bucket.ref
        else:
            result["Bucket"] = self.bucket
        return result


class Bucket(Resource):
    """S3 Bucket."""

    ATTRIBUTES = ("Arn", "DomainName")

    def __init__(
        self,
        name: str,
        access_control: AccessControl | None = None,
        bucket_name: str | None = None,
        versioning: bool = False,
    ) -> None:
        """Initialize a S3 bucket.

        :param name: logical name of the resource in the stack
        :param acccess_control: A canned access control list (ACL) that grants
            predefined permissions to the bucket. if None default is PRIVATE
        :param bucket_name: the bucket name in AWS. If set cloud formation will
            not be able to update settings of the buckets automatically.
        """
        super(Bucket, self).__init__(name, kind=AWSType.S3_BUCKET)
        if access_control is None:
            self.access_control = AccessControl.PRIVATE
        else:
            self.access_control = access_control
        self.bucket_name = bucket_name
        self.versioning = versioning

    @property
    def arn(self) -> GetAtt:
        return self.getatt("Arn")

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {
            "AccessControl": self.access_control.value,
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
                ]
            },
        }
        if self.bucket_name is not None:
            result["BucketName"] = self.bucket_name
        if self.versioning:
            result["VersioningConfiguration"] = {"Status": "Enabled"}
        else:
            result["VersioningConfiguration"] = {"Status": "Suspended"}
        return result
