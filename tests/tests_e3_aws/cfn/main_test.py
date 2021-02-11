from __future__ import absolute_import, division, print_function

import pytest
from botocore.stub import ANY, Stubber
from e3.aws import AWSEnv, default_region
from e3.aws.cfn import Stack
from e3.aws.cfn.s3 import Bucket


def test_stack_create():
    s = Stack(name="teststack")
    s.body
    assert True

    with pytest.raises(AssertionError):
        # Create a stack with an invalid name
        s = Stack(name="test_stack")


def test_stack_compose():
    s = Stack(name="teststack")
    s2 = Stack(name="teststack2")
    s2.add(Bucket("bucket1")).add(Bucket("bucket2"))
    s += s2
    assert len(s.export()["Resources"]) == 2


def test_create_stack():
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with default_region("us-east-1"):
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


def test_create_change_set():
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with default_region("us-east-1"):
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


def test_validate():
    s = Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"])
    with default_region("us-east-1"):
        cfn_client = aws_env.client("cloudformation", region="us-east-1")

        stubber = Stubber(cfn_client)
        stubber.add_response("validate_template", {}, {"TemplateBody": ANY})
        stubber.add_response("validate_template", {}, {"TemplateURL": ANY})
        with stubber:
            s.validate()
            s.validate(url="noprotocol://nothing")
