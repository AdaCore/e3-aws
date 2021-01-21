"""Provide IAM construct tests."""

from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere import Stack

EXPECTED_ROLE = {
    "TestRole": {
        "Properties": {
            "RoleName": "TestRole",
            "Description": "TestRole description",
            "MaxSessionDuration": 7200,
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


def test_role(stack: Stack) -> None:
    """Test IAM role creation.

    Creating a Role also tests PolicyDocument and Policystatement classes.
    """
    stack.add(
        Role(
            name="TestRole",
            description="TestRole description",
            max_session_duration=7200,
            principal={"Service": "test"},
            tags={"TestTagKey": "TestTagValue"},
        )
    )
    assert stack.export()["Resources"] == EXPECTED_ROLE
