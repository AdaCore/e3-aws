"""Provide Stack tests."""

from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws.troposphere import Stack


def test_instanciate() -> None:
    """Test stack instanciation."""
    stack = Stack("test-stack", "this is a test stack")
    assert stack


def test_add_and_get_item() -> None:
    """Test adding a construct and retrieving an AWSObject from a stack."""
    stack = Stack("test-stack", "this is a test stack")
    stack.add(Bucket("my-bucket"))
    my_bucket = stack["my-bucket"]
    assert my_bucket
