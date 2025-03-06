"""Provide S3 buckets."""

from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING


from troposphere import AccountId, AWSObject, s3, Ref, GetAtt

from e3.aws import name_to_id
from e3.aws.troposphere.awslambda import Function
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from e3.aws.troposphere.sns import Topic
from e3.aws.troposphere.sqs import Queue


if TYPE_CHECKING:
    from e3.aws.troposphere import Stack
    from typing import Any

# A default lifecycle rule to abort and delete incomplete multipart upload
# This rule is recommended by AWS Trusted advisor to avoid excess costs
DEFAULT_LIFECYCLE_RULE = s3.LifecycleRule(
    Id="AbortIncompleteMultipartUpload",
    AbortIncompleteMultipartUpload=s3.AbortIncompleteMultipartUpload(
        DaysAfterInitiation=7
    ),
    Prefix="",
    Status="Enabled",
)


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
        lifecycle_rules: list[s3.LifecycleRule] | None = None,
        default_bucket_encryption: (
            EncryptionAlgorithm | None
        ) = EncryptionAlgorithm.AES256,
        authorized_encryptions: list[EncryptionAlgorithm] | None = None,
        add_multipart_lifecycle_rule: bool = False,
        **bucket_kwargs: Any,
    ):
        """Initialize a bucket.

        :param name: bucket name
        :param enable_versioning: can be set to enable multiple versions of all
            objects in the bucket.
        :param lifecycle_rules: lifecycle rules for bucket objects
        :param default_bucket_encryption: type of the default bucket encryption.
        :param authorized_encryptions: types of the server side encryptions
            to authorize.
        :param add_multipart_lifecycle_rule: add default rule is to abort multipart
            uploads that remain incomplete after 7 days.
        :param bucket_kwargs: keyword arguments to pass to the bucket constructor
        """
        self.name = name
        self.enable_versioning = enable_versioning
        self.lifecycle_rules = lifecycle_rules

        if add_multipart_lifecycle_rule:
            self.lifecycle_rules = (
                self.lifecycle_rules + [DEFAULT_LIFECYCLE_RULE]
                if self.lifecycle_rules
                else [DEFAULT_LIFECYCLE_RULE]
            )

        self.default_bucket_encryption = default_bucket_encryption
        if authorized_encryptions is None:
            self.authorized_encryptions = [EncryptionAlgorithm.AES256]
        else:
            self.authorized_encryptions = authorized_encryptions
        self.lambda_configurations: list[
            tuple[dict[str, str], Function | None, str]
        ] = []
        self.topic_configurations: list[tuple[dict[str, str], Topic | None, str]] = []
        self.queue_configurations: list[tuple[dict[str, str], Queue | None, str]] = []
        self.depends_on: list[str] = []
        self.bucket_kwargs = bucket_kwargs

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

    @property
    def policy_document(self) -> PolicyDocument:
        """Return PolicyDocument to be attached to the bucket."""
        return PolicyDocument(statements=self.policy_statements)

    def add_notification_configuration(
        self,
        event: str,
        target: Function | Topic | Queue | str,
        permission_suffix: str,
        s3_filter: s3.Filter | None = None,
    ) -> None:
        """Add a configuration to bucket notification rules.

        :param event: the S3 bucket event for which to invoke or notify the target
        :param target: target to invoke or notify when the specified event type occurs
        :param permission_suffix: a name suffix for permissions or policy objects
        :param s3_filter: the filtering rules that determine which objects invoke
            or notify the target
        """
        params = {"Event": event}
        if s3_filter:
            params["Filter"] = s3_filter

        if isinstance(target, Topic):
            params["Topic"] = target.arn
            self.topic_configurations.append((params, target, permission_suffix))
        elif isinstance(target, Function):
            params["Function"] = target.arn
            self.lambda_configurations.append((params, target, permission_suffix))
        elif isinstance(target, Queue):
            params["Queue"] = target.arn
            self.queue_configurations.append((params, target, permission_suffix))
        elif ":sns:" in target:
            params["Topic"] = target
            self.topic_configurations.append((params, None, permission_suffix))
        elif ":lambda:" in target:
            params["Function"] = target
            self.lambda_configurations.append((params, None, permission_suffix))
        elif ":sqs:" in target:
            params["Queue"] = target
            self.queue_configurations.append((params, None, permission_suffix))

    @property
    def notification_setup(
        self,
    ) -> tuple[s3.NotificationConfiguration, list[AWSObject]]:
        """Return notification configuration and associated resources."""
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
                if function:
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
            for _, topic, _ in self.topic_configurations:
                if topic:
                    topic_policy_name = topic.add_allow_service_to_publish_statement(
                        applicant=f"{name_to_id(self.name)}",
                        service="s3",
                        condition={"ArnLike": {"aws:SourceArn": self.arn}},
                    )
                    self.depends_on.append(topic_policy_name)
        if self.queue_configurations:
            params.update(
                {
                    "QueueConfigurations": [
                        s3.QueueConfigurations(**queue_params)
                        for queue_params, _, _ in self.queue_configurations
                    ]
                }
            )
            for _, queue, _ in self.queue_configurations:
                if queue:
                    queue_policy_name = queue.add_allow_service_to_write_statement(
                        applicant=f"{name_to_id(self.name)}",
                        service="s3",
                        condition={"ArnLike": {"aws:SourceArn": self.arn}},
                    )
                    self.depends_on.append(queue_policy_name)

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

        attr = {"DeletionPolicy": "Retain"}
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

        attr |= self.bucket_kwargs
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

    @property
    def domain_name(self):
        return GetAtt(name_to_id(self.name), "DomainName")

    @property
    def regional_domain_name(self):
        return GetAtt(name_to_id(self.name), "RegionalDomainName")

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
