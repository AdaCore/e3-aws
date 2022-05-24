"""Provide Cloudformation construct tests."""

from __future__ import annotations

from troposphere import AccountId, Equals

from e3.aws.troposphere import Stack
from e3.aws.troposphere.cloudformation import StackSet
from e3.aws.troposphere.iam.role import Role


EXPECTED_TEMPLATE = {
    "StackSetTest": {
        "Properties": {
            "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": False},
            "CallAs": "SELF",
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "Description": "this is a test",
            "PermissionModel": "SERVICE_MANAGED",
            "StackSetName": "stack-set-test",
            "TemplateURL": "https://cfn_bucket.s3.amazonaws.com/templates/"
            "stack-set-test-template.yaml",
            "OperationPreferences": {
                "FailureToleranceCount": 4,
                "MaxConcurrentCount": 5,
            },
            "StackInstancesGroup": [
                {
                    "DeploymentTargets": {"OrganizationalUnitIds": ["test-ou"]},
                    "Regions": ["eu-west-1"],
                }
            ],
        },
        "Type": "AWS::CloudFormation::StackSet",
    }
}


def test_stackset(stack: Stack) -> None:
    """test Cloudformation stack set creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    stack_set = StackSet(
        name="stack-set-test",
        description="this is a test",
        regions=["eu-west-1"],
        ous=["test-ou"],
        failure_tolerance_count=4,
        max_concurrent_count=5,
    )

    stack_set.add(
        Role(
            name="TestRole",
            description="TestRole description",
            trust={"Service": "test"},
        )
    )
    stack_set.add_condition("", Equals(AccountId, "test_account_id"))
    stack.add(stack_set)
    assert stack.export()["Resources"] == EXPECTED_TEMPLATE
