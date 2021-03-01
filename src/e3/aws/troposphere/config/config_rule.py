"""Provide AWS Config configuration rules."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING


from troposphere import AWSObject, config

from e3.aws import name_to_id
from e3.aws.troposphere import Construct


if TYPE_CHECKING:
    from typing import Any
    from e3.aws.troposphere import Stack


@dataclass(frozen=True)
class ConfigRule(Construct):
    """Define a configuration rule.

    :param name: name of the rule
    :param source_identifier: predefined identifier of an existing AWS Config
        managed rule
    :param description: rule description
    :param input_parameters: input parameters passed to the AWS Config rule
        Lambda function
    :param scope: defines which resources can trigger an evaluation for the rule
    """

    name: str
    source_identifier: str = ""
    description: str = ""
    input_parameters: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return troposphere objects defining the configuration rule."""
        return [
            config.ConfigRule(
                name_to_id(self.name),
                ConfigRuleName=self.name,
                Description=self.description,
                InputParameters=self.input_parameters,
                Scope=config.Scope.from_dict(
                    name_to_id(f"configscope{self.name}"), self.scope
                ),
                Source=config.Source.from_dict(
                    name_to_id(f"configsource{self.name}"),
                    {"Owner": "AWS", "SourceIdentifier": self.source_identifier},
                ),
                DependsOn="ConfigRecorder",
            )
        ]


@dataclass(frozen=True)
class S3ConfigRule(ConfigRule):
    """Define a S3 Configuration rule.

    :param name: name of the rule
    :param source_identifier: predefined identifier of an existing AWS Config
        managed rule
    :param description: rule description
    :param input_parameters: input parameters passed to the AWS Config rule
        Lambda function
    """

    name: str
    source_identifier: str
    description: str
    input_parameters: dict = field(default_factory=dict)

    scope: dict = field(
        default_factory=lambda: {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
        init=False,
    )


S3BucketPublicWriteProhibited = S3ConfigRule(
    name="s3-bucket-public-write-prohibited",
    source_identifier="S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
    description=(
        "Checks that your S3 buckets do not allow public write access."
        "If an S3 bucket policy or bucket ACL allows public write access, "
        "the bucket is noncompliant."
    ),
)

S3BucketPublicReadProhibited = S3ConfigRule(
    name="s3-bucket-public-read-prohibited",
    source_identifier="S3_BUCKET_PUBLIC_READ_PROHIBITED",
    description=(
        "Checks that your S3 buckets do not allow public read access."
        "If an S3 bucket policy or bucket ACL allows public read access, "
        "the bucket is noncompliant."
    ),
)

S3BucketServerSideEncryptionEnabled = S3ConfigRule(
    name="s3-bucket-server-side-encryption-enabled",
    source_identifier="S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    description=(
        "Checks that your Amazon S3 bucket either has S3 default encryption "
        "enabled or that the S3 bucket policy explicitly denies put-object "
        "requests without server side encryption."
    ),
)


S3BucketSSLRequestsOnly = S3ConfigRule(
    name="s3-bucket-ssl-requests-only",
    source_identifier="S3_BUCKET_SSL_REQUESTS_ONLY",
    description=(
        "Checks whether S3 buckets have policies that require requests to "
        "use Secure Socket Layer (SSL)."
    ),
)

IAMUserNoPoliciesCheck = ConfigRule(
    name="iam-user-no-policies-check",
    source_identifier="IAM_USER_NO_POLICIES_CHECK",
    description=(
        "Checks that none of your IAM users have policies attached. "
        "IAM users must inherit permissions from IAM groups or roles."
    ),
    scope={"ComplianceResourceTypes": ["AWS::IAM::User"]},
)
