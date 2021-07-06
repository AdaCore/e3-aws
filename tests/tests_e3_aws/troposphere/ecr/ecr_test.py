"""Provide ecr construct tests."""

from e3.aws.troposphere import Stack
from e3.aws.troposphere.ecr.repository import Repository

EXPECTED_REPOSITORY = {
    "TestRepository": {
        "Properties": {
            "ImageScanningConfiguration": {"ScanOnPush": True},
            "ImageTagMutability": "IMMUTABLE",
            "RepositoryName": "test-repository",
            "Tags": [{"Key": "Name", "Value": "test-repository"}],
        },
        "Type": "AWS::ECR::Repository",
    }
}


def test_ecr_repository(stack: Stack) -> None:
    """Test ECR repository scheduled rule creation."""
    stack.add(Repository(name="test-repository"))
    assert stack.export()["Resources"] == EXPECTED_REPOSITORY
