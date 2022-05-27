"""Provide SecretsManager constructs tests."""
from __future__ import annotations
import json
import os

from e3.aws.troposphere import Stack
from e3.aws.troposphere.secretsmanager import Secret, RotationSchedule
from e3.aws.troposphere.awslambda import PyFunction

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_secret_rotation_schedule(stack: Stack) -> None:
    """Test RotatingSecret."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    secret = Secret(name="TestSecret", description="TestSecret description")
    rotation_function = PyFunction(
        name="myrotationlambda",
        description="this is a test",
        role="somearn",
        runtime="python3.9",
        code_dir="my_code_dir",
        handler="app.main",
    )
    rotation_schedule = RotationSchedule(
        secret=secret,
        rotation_function=rotation_function,
        schedule_expression="rate(4 days)",
    )
    for el in (secret, rotation_function, rotation_schedule):
        stack.add(el)
    with open(os.path.join(TEST_DIR, "secret_rotation_schedule.json")) as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template
