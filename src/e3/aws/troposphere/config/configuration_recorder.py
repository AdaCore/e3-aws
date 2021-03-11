"""Provide constructs to define aws config rules."""

from __future__ import annotations
from typing import TYPE_CHECKING


from troposphere import AWSObject, AccountId, iam, config, Join

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws.troposphere.iam.policy_statement import PolicyStatement

if TYPE_CHECKING:
    from typing import List
    from e3.aws.troposphere import Stack


class ConfigurationRecorder(Construct):
    """Define a ConfigurationRecorder and associated ressources."""

    def __init__(self, bucket_name: str):
        """Initializae a ConfigurationRecorder.

        :param name: The name of the Amazon S3 bucket to create and to which AWS
            Config will deliver configuration snapshots and configuration history
            files.
        """
        self.bucket_name = bucket_name

    def resources(self, stack: Stack) -> List[AWSObject]:
        """Build and return objects associated with the configuration recorder.

        Return a configuration recorder and a delivery channel with its s3 bucket
        """
        aws_objects = []

        config_role = iam.ServiceLinkedRole.from_dict(
            "AWSServiceRoleForConfig", {"AWSServiceName": "config.amazonaws.com"}
        )
        aws_objects.append(config_role)

        # Add the config recorder
        recording_group = config.RecordingGroup(
            AllSupported=True, IncludeGlobalResourceTypes=True
        )

        aws_objects.append(
            config.ConfigurationRecorder(
                name_to_id("ConfigRecorder"),
                Name="ConfigRecorder",
                RecordingGroup=recording_group,
                RoleARN=Join(
                    ":",
                    [
                        "arn",
                        "aws",
                        "iam:",
                        AccountId,
                        (
                            "role/aws-service-role/"
                            "config.amazonaws.com/AWSServiceRoleForConfig"
                        ),
                    ],
                ),
                DependsOn=config_role.title,
            )
        )

        # Create an S3 bucket for the delivery
        bucket = Bucket(name=self.bucket_name)
        bucket.policy_statements += [
            PolicyStatement(
                action="s3:GetBucketAcl",
                effect="Allow",
                principal={"Service": "config.amazonaws.com"},
                resource=bucket.arn,
            ),
            PolicyStatement(
                action="s3:PutObject",
                effect="Allow",
                condition={
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
                principal={"Service": "config.amazonaws.com"},
                resource=Join("", [bucket.arn, "/AWSLogs/", AccountId, "/Config/*"]),
            ),
        ]

        aws_objects.extend(bucket.resources(stack=stack))

        # Create the delivery channel to the S3 bucket
        aws_objects.append(
            config.DeliveryChannel(
                name_to_id("DeliveryChannel"),
                Name="DeliveryChannel",
                S3BucketName=bucket.ref,
            )
        )

        return aws_objects
