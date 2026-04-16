"""Provide tests for CloudFormation stack operations."""

import pytest
from botocore.stub import ANY, Stubber

from e3.aws import AWSEnv, DefaultRegion
from e3.aws.cfn import Stack
from e3.aws.cfn.s3 import Bucket


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
