"""Provide Stack tests."""

import json
from pathlib import Path
import pytest
from troposphere import Parameter, Output, Export

from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws.troposphere import Stack

TEST_DIR = Path(__file__).parent


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


def test_add_parameters() -> None:
    """Test adding parameters to a stack."""
    stack = Stack("test-stack", "this is a test stack")
    stack.add_parameter(
        Parameter(
            "MyParameter1",
            Description="My first parameter",
            Type="String",
        )
    )
    stack.add_parameter(
        [
            Parameter(
                "MyParameter2",
                Description="My second parameter",
                Type="int",
                Default="Parameter2",
                MinValue=0,
                MaxValue=10,
            ),
            Parameter(
                "MyParameter3",
                Description="My third parameter",
                Type="String",
            ),
        ]
    )

    with open(TEST_DIR / "stack_with_parameters.json") as fd:
        expected_template = json.load(fd)

    assert stack.export()["Parameters"] == expected_template


def test_add_outputs() -> None:
    """Test adding outputs to a stack."""
    stack = Stack("test-stack", "this is a test stack")
    stack.add(Bucket("my-bucket"))
    stack.add_output(
        Output("MyOutput1", Description="My first output", Value=Export(name="Output1"))
    )
    stack.add_output(
        [
            Output(
                "MyOutput2",
                Description="My second output",
                Value=Export(name="Output2"),
            ),
            Output(
                "MyOutput3", Description="My third output", Value=Export(name="Output3")
            ),
        ]
    )

    with open(TEST_DIR / "stack_with_outputs.json") as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_update_output() -> None:
    """Test updating an already existing output."""
    o = Output("Output", Description="My output", Value=Export(name="Output"))
    stack = Stack("test-stack", "this is a test stack")
    stack.add_output(o)

    # This one should fail because of the duplicate key
    with pytest.raises(match='duplicate key "Output" detected'):
        stack.add_output(o)

    # This one should update the output
    o.Description = "Updated output"
    stack.add_output(o, update_if_exist=True)

    assert stack.export()["Outputs"] == {
        "Output": {
            "Description": "Updated output",
            "Value": {
                "Name": "Output",
            },
        },
    }


def test_extend() -> None:
    """Test adding multiple construct and retrieving an AWSObject from a stack."""
    stack = Stack("test-stack", "this is a test stack")
    stack.extend([Bucket("my-bucket-a"), Bucket("my-bucket-b")])
    my_bucket = stack["my-bucket-b"]
    assert my_bucket
