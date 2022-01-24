"""Provide S3 buckets."""

from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING


from troposphere import AccountId, AWSObject, s3, Ref

from e3.aws import name_to_id
from e3.aws.troposphere.awslambda import Function
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from e3.aws.troposphere.sns import Topic
from e3.aws.troposphere.sqs import Queue


if TYPE_CHECKING:
    from typing import Optional, Tuple
    from e3.aws.troposphere import Stack
    from e3.aws.troposphere.iam.policy_statement import ConditionType


class EncryptionAlgorithm(Enum):
    """Provide an Enum to describe encryption algorithms."""

    AES256 = "AES256"
    KMS = "aws:kms"


class Bucket(Construct):
    """Define a S3 bucket construct with security parameters and a security policy."""

    def __init__(
        self,
        name: str,
        enable_versioning: bool = True,
        lifecycle_rules: Optional[list[s3.LifecycleRule]] = None,
        default_bucket_encryption: Optional[
            EncryptionAlgorithm
        ] = EncryptionAlgorithm.AES256,
        authorized_encryptions: Optional[list[EncryptionAlgorithm]] = None,
    ):
        """Initialize a bucket.

        :param name: bucket name
        :param enable_versioning: can be set to enable multiple versions of all
            objects in the bucket.
        :param lifecycle_rules: lifecycle rules for bucket objects
        :param default_bucket_encryption: type of the default bucket encryption.
        :param authorized_encryptions: types of the server side encryptions
            to authorize.
        """
        self.name = name
        self.enable_versioning = enable_versioning
        self.lifecycle_rules = lifecycle_rules
        self.default_bucket_encryption = default_bucket_encryption
        if authorized_encryptions is None:
            self.authorized_encryptions = [EncryptionAlgorithm.AES256]
        else:
            self.authorized_encryptions = authorized_encryptions
        self.lambda_configurations: list[Tuple[dict[str, str], Function, str]] = []
        self.topic_configurations: list[Tuple[dict[str, str], Topic, str]] = []
        self.queue_configurations: list[Tuple[dict[str, str], Queue, str]] = []
        self.depends_on: list[str] = []

        # Add minimal policy statements
        self.policy_statements = [
            # Deny any request not using https transport protocol
            PolicyStatement(
                action="s3:*",
                effect="Deny",
                resource=self.all_objects_arn,
                principal={"AWS": "*"},
                condition={"Bool": {"aws:SecureTransport": "false"}},
            )
        ]

        assert (
            self.authorized_encryptions
        ), "At least one authorized s3 encryption should be provided"

        # The one element case is needed for retrocompatibility
        # with stacks deployed with older versions of e3-aws
        condition: ConditionType
        if len(self.authorized_encryptions) == 1:
            condition = {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": self.authorized_encryptions[
                        0
                    ].value
                }
            }
        else:
            condition = {
                "ForAllValues:StringNotEquals": {
                    "s3:x-amz-server-side-encryption": [
                        enc.value for enc in self.authorized_encryptions
                    ]
                }
            }

        self.policy_statements.extend(
            [
                # Deny to store object not encrypted with AES256 encryption
                PolicyStatement(
                    action="s3:PutObject",
                    effect="Deny",
                    resource=self.all_objects_arn,
                    principal={"AWS": "*"},
                    condition=condition,
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
        )

    @property
    def policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the bucket."""
        return PolicyDocument(statements=self.policy_statements)

    def add_notification_configuration(
        self,
        event: str,
        target: Function | Topic | Queue | str,
        permission_suffix: str,
        s3_filter: Optional[s3.Filter] = None,
    ) -> None:
        """Add a configuration to bucket notification rules.

        :param event: the S3 bucket event for which to invoke the Lambda function
        :param function: function to invoke when the specified event type occurs
        :param permission_suffix: a name suffix for permissions or policy objects
        :param s3_filter: the filtering rules that determine which objects invoke
            the AWS Lambda function
        """
        params = {"Event": event}
        if s3_filter:
            params["Filter"] = s3_filter

        if isinstance(target, Topic):
            params["Topic"] = target.arn
            self.topic_configurations.append((params, target, permission_suffix))
        if isinstance(target, Function):
            params["Function"] = target.arn
            self.lambda_configurations.append((params, target, permission_suffix))
        elif isinstance(target, Queue):
            params["Queue"] = target.arn
            self.queue_configurations.append((params, target, permission_suffix))

    @property
    def notification_setup(
        self,
    ) -> Tuple[s3.NotificationConfiguration, list[AWSObject]]:
        """Return notifcation configuration and associated resources."""
        notification_resources = []
        notification_config = None
        params = {}
        if self.lambda_configurations:
            params.update(
                {
                    "LambdaConfigurations": [
                        s3.LambdaConfigurations(**lambda_params)
                        for lambda_params, _, _ in self.lambda_configurations
                    ]
                }
            )
            # Add Permission invoke for lambdas
            for _, function, suffix in self.lambda_configurations:
                notification_resources.append(
                    function.invoke_permission(
                        name_suffix=suffix,
                        service="s3",
                        source_arn=self.arn,
                        source_account=AccountId,
                    )
                )
        if self.topic_configurations:
            params.update(
                {
                    "TopicConfigurations": [
                        s3.TopicConfigurations(**topic_params)
                        for topic_params, _, _ in self.topic_configurations
                    ]
                }
            )
            # Add policy allowing to publish to topics
            for _, topic, suffix in self.topic_configurations:
                topic_policy = topic.allow_publish_policy(
                    service="s3",
                    name_suffix=suffix,
                    condition={"ArnLike": {"aws:SourceArn": self.arn}},
                )
                notification_resources.append(topic_policy)
                self.depends_on.append(topic_policy)
        if self.queue_configurations:
            params.update(
                {
                    "QueueConfigurations": [
                        s3.QueueConfigurations(**queue_params)
                        for queue_params, _, _ in self.queue_configurations
                    ]
                }
            )
            for _, queue, suffix in self.queue_configurations:

                queue_policy = queue.allow_service_to_write(
                    service="s3",
                    name_suffix=suffix,
                    condition={"ArnLike": {"aws:SourceArn": self.arn}},
                )
                notification_resources.append(queue_policy)
                self.depends_on.append(queue_policy)

        if params:
            notification_config = s3.NotificationConfiguration(
                name_to_id(self.name + "NotifConfig"), **params
            )

        return notification_config, notification_resources

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Construct and return a s3.Bucket and its associated s3.BucketPolicy."""
        # Handle versioning configuration
        optional_resources = []
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
        bucket_encryption = None
        if self.default_bucket_encryption:
            bucket_encryption = s3.BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    s3.ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=s3.ServerSideEncryptionByDefault(
                            SSEAlgorithm=self.default_bucket_encryption.value
                        )
                    )
                ]
            )

        lifecycle_config = None
        if self.lifecycle_rules:
            lifecycle_config = s3.LifecycleConfiguration(
                name_to_id(self.name) + "LifeCycleConfig", Rules=self.lifecycle_rules
            )

        notification_config, notification_resources = self.notification_setup
        optional_resources.extend(notification_resources)

        attr = {}
        for key, val in {
            "BucketName": self.name,
            "BucketEncryption": bucket_encryption,
            "PublicAccessBlockConfiguration": public_access_block_config,
            "VersioningConfiguration": s3.VersioningConfiguration(
                Status=versioning_status
            ),
            "LifecycleConfiguration": lifecycle_config,
            "NotificationConfiguration": notification_config,
            "DependsOn": self.depends_on,
        }.items():
            if val:
                attr[key] = val

        return [
            s3.Bucket(name_to_id(self.name), **attr),
            s3.BucketPolicy(
                name_to_id(self.name) + "Policy",
                Bucket=self.ref,
                PolicyDocument=self.policy_document.as_dict,
            ),
            *optional_resources,
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
