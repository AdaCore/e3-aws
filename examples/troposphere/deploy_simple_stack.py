"""E3 troposphere usage example."""

from __future__ import annotations
import logging

from troposphere import Ref

from e3.aws import Session, Stack

from e3.aws.troposphere.config.config_rule import (
    S3BucketPublicWriteProhibited,
    S3BucketPublicReadProhibited,
    S3BucketServerSideEncryptionEnabled,
    S3BucketSSLRequestsOnly,
    IAMUserNoPoliciesCheck,
)
from e3.aws.troposphere.config.configuration_recorder import ConfigurationRecorder
from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws.troposphere.s3.managed_policy import S3AccessManagedPolicy

logging.basicConfig(level=logging.INFO)


def build_and_deploy_tstacks() -> None:
    """Build and deploy two simple troposphere stacks.

    Two stacks in two different regions are deployed. An us stack define only a secure
    bucket. An eu stack define secure s3 buckets, a role to add object to the eu bucket
    and a AWSConfig recorder with rules that check s3 buckets security configurations
    across both regions.
    """
    sessions = {
        "eu": Session(regions=["eu-west-1"]),
        "us": Session(regions=["us-east-1"]),
    }
    stack = {}
    for region in ("eu", "us"):
        stack[region] = Stack(
            f"e3-example-{region}",
            sessions[region],
            opts={"Capabilities": ["CAPABILITY_NAMED_IAM"]},
        )

    # Add a s3 secure bucket in each region
    stack["eu"].add_construct([Bucket(name="e3-l1-example")])
    stack["us"].add_construct([Bucket(name="e3-l2-example")])

    # Define a new IAM-Roles that will be used to acces e3-l1-example bucket
    stack["eu"].add_construct(
        [
            Role(
                name="L1WriteRole",
                description="Role to write to l1 buckets",
                principal={"Service": "ecs-tasks.amazonaws.com"},
            )
        ]
    )

    # Define a new IAM-Policy to putObject in e3-l1-example bucket
    # and attach the L1WriteRole role to it
    stack["eu"].add_construct(
        [
            S3AccessManagedPolicy(
                name="S3WriteAccess",
                buckets=["e3-l1-example"],
                action=["s3:PutObject"],
                roles=[Ref(stack["eu"]["L1WriteRole"])],
            )
        ]
    )

    # Add AWS config rules to check S3 buckets security configuration.
    # This should only be defined in one region
    for region in ("eu",):
        stack[region].add_construct(
            [ConfigurationRecorder(bucket_name="config-bucket-example")]
        )

    for region in ("eu",):
        stack[region].add_construct(
            [
                S3BucketPublicWriteProhibited,
                S3BucketPublicReadProhibited,
                S3BucketServerSideEncryptionEnabled,
                S3BucketSSLRequestsOnly,
                IAMUserNoPoliciesCheck,
            ]
        )

    # Deploy stacks
    for region in ("eu", "us"):
        stack[region].deploy()


def main() -> None:
    """Provide entry point."""
    build_and_deploy_tstacks()

    return


if __name__ == "__main__":
    main()
