"""Provide IAM construct tests."""

import os
import json
from e3.aws.troposphere.iam.role import Role, PolicyDocument
from e3.aws.troposphere.iam.policy_statement import Allow, Trust
from e3.aws.troposphere import Stack

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
EXPECTED_ROLE = {
    "TestRole": {
        "Properties": {
            "RoleName": "TestRole",
            "Description": "TestRole description",
            "MaxSessionDuration": 7200,
            "Path": "/",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "test"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "Tags": [
                {"Key": "Name", "Value": "TestRole"},
                {"Key": "TestTagKey", "Value": "TestTagValue"},
            ],
        },
        "Type": "AWS::IAM::Role",
    }
}

EXPECTED_TRUST_ROLES = {
    "TestRole": {
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Action": ["sts:SetSourceIdentity"],
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": ["arn:aws:iam::123456789012:role/OtherRole"]
                        },
                    }
                ],
                "Version": "2012-10-17",
            },
            "Description": "TestRole description",
            "Path": "/",
            "RoleName": "TestRole",
            "Tags": [{"Key": "Name", "Value": "TestRole"}],
        },
        "Type": "AWS::IAM::Role",
    },
}


def test_role(stack: Stack) -> None:
    """Test IAM role creation.

    Creating a Role also tests PolicyDocument and Policystatement classes.
    """
    stack.add(
        Role(
            name="TestRole",
            description="TestRole description",
            max_session_duration=7200,
            trust={"Service": "test"},
            tags={"TestTagKey": "TestTagValue"},
        )
    )
    assert stack.export()["Resources"] == EXPECTED_ROLE


def test_statement() -> None:
    """Test an IAM policy statement creation."""
    statement = Allow(action="s3:putObject", resource="*")
    assert statement.as_dict == {
        "Action": "s3:putObject",
        "Effect": "Allow",
        "Resource": "*",
    }


def test_trust_roles(stack: Stack) -> None:
    """Test IAM role creation.

    Creating a Role that trust another Role
    """
    stack.add(
        Role(
            name="TestRole",
            description="TestRole description",
            trust=Trust(
                roles=[(123456789012, "OtherRole")], actions=["sts:SetSourceIdentity"]
            ),
        )
    )
    assert stack.export()["Resources"] == EXPECTED_TRUST_ROLES


def test_role_with_inline(stack: Stack) -> None:
    stack.add(
        Role(
            name="TestRoleWithPolicies",
            description="TestRoleWithPolicies description",
            trust=Trust(services=["ec2"]),
            inline_policies={
                "PolicyDocument": PolicyDocument(
                    statements=[
                        Allow(action="iam:*", resource="*"),
                        Allow(action="logs:*", resource="*"),
                    ]
                ),
                "PolicyStatement": Allow(action="s3:Get*"),
                "Dict": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}
                    ],
                },
            },
        )
    )

    with open(os.path.join(TEST_DIR, "role_with_inline.json")) as fd:
        expected_stack = json.load(fd)

    assert stack.export()["Resources"] == expected_stack
