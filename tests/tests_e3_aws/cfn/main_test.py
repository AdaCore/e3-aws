"""Provide tests for CloudFormation stack operations."""

import logging
from datetime import datetime, timezone

import pytest
from botocore.stub import ANY, Stubber

from e3.aws import AWSEnv, DefaultRegion
from e3.aws.cfn import Stack
from e3.aws.cfn.s3 import Bucket

UTC = timezone.utc


def test_stack_create() -> None:
    """Test stack creation."""
    s = Stack(name="teststack")
    assert s.body is not None

    with pytest.raises(AssertionError):
        # Create a stack with an invalid name
        s = Stack(name="test_stack")


def test_stack_compose() -> None:
    """Test stack composition."""
    s = Stack(name="teststack")
    s2 = Stack(name="teststack2")
    s2.add(Bucket("bucket1")).add(Bucket("bucket2"))
    s += s2
    expected_resources = 2
    assert len(s.export()["Resources"]) == expected_resources


def test_create_stack() -> None:
    """Test create stack API call."""
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with DefaultRegion("us-east-1"):
        cfn_client = aws_env.client("cloudformation", region="us-east-1")

        stubber = Stubber(cfn_client)
        stubber.add_response(
            "create_stack",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "ClientRequestToken": ANY,
                "TemplateBody": ANY,
            },
        )
        stubber.add_response(
            "create_stack",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "ClientRequestToken": ANY,
                "TemplateURL": ANY,
            },
        )
        with stubber:
            s.create()
            s.create(url="noprotocol://nothing")


def test_create_change_set() -> None:
    """Test create change set API call."""
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with DefaultRegion("us-east-1"):
        cfn_client = aws_env.client("cloudformation", region="us-east-1")

        stubber = Stubber(cfn_client)
        stubber.add_response(
            "create_change_set",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "ChangeSetName": "name1",
                "TemplateBody": ANY,
            },
        )
        stubber.add_response(
            "create_change_set",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "ChangeSetName": "name2",
                "StackName": "teststack",
                "TemplateURL": ANY,
            },
        )
        with stubber:
            s.create_change_set("name1")
            s.create_change_set("name2", url="noprotocol://nothing")


def test_create_change_set_role_arn() -> None:
    """Test create change set with role ARN."""
    s = Stack(name="teststack", cfn_role_arn="arn:aws:iam::123456789012:role/S3Access")

    aws_env = AWSEnv(regions=["us-east-1"])
    with DefaultRegion("us-east-1"):
        cfn_client = aws_env.client("cloudformation", region="us-east-1")

        stubber = Stubber(cfn_client)
        stubber.add_response(
            "create_change_set",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "ChangeSetName": "name1",
                "TemplateBody": ANY,
                "RoleARN": "arn:aws:iam::123456789012:role/S3Access",
            },
        )
        with stubber:
            s.create_change_set("name1")


def test_validate() -> None:
    """Test stack template validation."""
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with DefaultRegion("us-east-1"):
        cfn_client = aws_env.client("cloudformation", region="us-east-1")

        stubber = Stubber(cfn_client)
        stubber.add_response("validate_template", {}, {"TemplateBody": ANY})
        stubber.add_response("validate_template", {}, {"TemplateURL": ANY})
        with stubber:
            s.validate()
            s.validate(url="noprotocol://nothing")


def test_wait_review_in_progress(caplog: pytest.LogCaptureFixture) -> None:
    """Test that wait() returns immediately when status is REVIEW_IN_PROGRESS.

    REVIEW_IN_PROGRESS is a stable state (stack awaiting change-set execution),
    not a transient operation, so wait() must not poll further.
    """
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with DefaultRegion("us-east-1"):
        cfn_client = aws_env.client("cloudformation", region="us-east-1")

        stubber = Stubber(cfn_client)
        # state() called at the start of wait()
        stubber.add_response(
            "describe_stacks",
            service_response={
                "Stacks": [
                    {
                        "StackName": "teststack",
                        "CreationTime": datetime(2024, 1, 1, tzinfo=UTC),
                        "StackStatus": "REVIEW_IN_PROGRESS",
                        "StackId": "teststack",
                    }
                ]
            },
            expected_params={"StackName": "teststack"},
        )
        # events() called once after the loop to drain last events.
        # Include a real REVIEW_IN_PROGRESS event so StackEvent.from_dict()
        # and StackEventStatus.from_str() exercise the REVIEW parser branch.
        stubber.add_response(
            "describe_stack_events",
            service_response={
                "StackEvents": [
                    {
                        "StackId": "teststack",
                        "EventId": "evt-1",
                        "StackName": "teststack",
                        "LogicalResourceId": "teststack",
                        "PhysicalResourceId": "teststack",
                        "ResourceType": "AWS::CloudFormation::Stack",
                        "Timestamp": datetime(2024, 1, 1, tzinfo=UTC),
                        "ResourceStatus": "REVIEW_IN_PROGRESS",
                        "ClientRequestToken": s.uuid,
                    },
                    {
                        "StackId": "teststack",
                        "EventId": "evt-2",
                        "StackName": "teststack",
                        "LogicalResourceId": "teststack",
                        "PhysicalResourceId": "teststack",
                        "ResourceType": "AWS::CloudFormation::Stack",
                        "Timestamp": datetime(2024, 1, 1, tzinfo=UTC),
                        "ResourceStatus": "CREATE_IN_PROGRESS",
                        "ClientRequestToken": s.uuid,
                    },
                ]
            },
            expected_params={"StackName": "teststack"},
        )

        with stubber, caplog.at_level(logging.INFO, logger="e3.aws.cfn"):
            result = s.wait()

    assert result == "REVIEW_IN_PROGRESS"
    assert caplog.text.count("review started   ()") == 1
    assert caplog.text.count("creation started ()") == 1


def test_stack_exists_review_in_progress() -> None:
    """Test that exists() returns True for a stack in REVIEW_IN_PROGRESS status."""
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with DefaultRegion("us-east-1"):
        cfn_client = aws_env.client("cloudformation", region="us-east-1")

        stubber = Stubber(cfn_client)
        stubber.add_response(
            "describe_stacks",
            service_response={
                "Stacks": [
                    {
                        "StackName": "teststack",
                        "CreationTime": datetime(2024, 1, 1, tzinfo=UTC),
                        "StackStatus": "REVIEW_IN_PROGRESS",
                        "StackId": "teststack",
                    }
                ]
            },
            expected_params={"StackName": "teststack"},
        )

        with stubber:
            assert s.exists() is True
