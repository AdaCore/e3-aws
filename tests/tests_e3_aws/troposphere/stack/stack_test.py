"""Provide Stack tests."""

from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws import Session, Stack


def test_instanciate() -> None:
    """Test stack instanciation."""
    stack = Stack("test-stack", Session(regions=["eu-west-1"]), opts=None)
    assert stack


def test_add_and_get_item() -> None:
    """Test adding a construct and retrieving an AWSObject from a stack."""
    stack = Stack("test-stack", Session(regions=["eu-west-1"]), opts=None)
    stack.add_construct([Bucket("my-bucket")])
    my_bucket = stack["my-bucket"]
    assert my_bucket
