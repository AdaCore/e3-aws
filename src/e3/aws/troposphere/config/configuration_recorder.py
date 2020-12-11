"""Provide constructs to define aws config rules."""

from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List

from troposphere import AWSObject, AccountId, iam, config, Join

from e3.aws import Construct, name_to_id
from e3.aws.troposphere.s3.bucket import AWSConfigBucket


@dataclass(frozen=True)
class ConfigurationRecorder(Construct):
    """Define a ConfigurationRecorder and associated ressources.

    :param name: The name of the Amazon S3 bucket to create and to which AWS
        Config will deliver configuration snapshots and configuration history
        files
    """

    bucket_name: str

    @property
    def resources(self) -> List[AWSObject]:
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

        # Add a delivery channel and an associated s3 bucket
        aws_objects.extend(AWSConfigBucket(name=f"{self.bucket_name}").resources)
        aws_objects.append(
            config.DeliveryChannel(
                name_to_id("DeliveryChannel"),
                Name="DeliveryChannel",
                S3BucketName=f"{self.bucket_name}",
                DependsOn=[name_to_id(f"{self.bucket_name}")],
            )
        )

        return aws_objects
