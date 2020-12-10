"""Provide IAM construct tests."""

from e3.aws.troposphere.iam.role import Role
from e3.aws import Stack

EXPECTED_ROLE = {
    "TestRole": {
        "Properties": {
            "RoleName": "TestRole",
            "Description": "TestRole description",
            "ManagedPolicyArns": [],
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
        },
        "Type": "AWS::IAM::Role",
    }
}


def test_role(stack: Stack) -> None:
    """Test IAM role creation.

    Creating a Role also tests PolicyDocument and Policystatement classes.
    """
    stack.add(
        Role(
            name="TestRole",
            description="TestRole description",
            principal={"Service": "test"},
        )
    )
    assert stack.export()["Resources"] == EXPECTED_ROLE
