"""Provide SecretsManager constructs tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import Alias, PyFunction
from e3.aws.troposphere.secretsmanager import RotationSchedule, Secret

TEST_DIR = Path(__file__).resolve().parent


@pytest.mark.parametrize(
    "alias",
    [
        # The rotation schedule invokes the function without alias
        None,
        # The rotation schedule invokes the function with the prod alias
        "prod",
    ],
)
def test_secret_rotation_schedule(alias: str | None, stack: Stack) -> None:
    """Test RotatingSecret.

    :param alias: name of the function alias
    :param stack: the stack
    """
    secret = Secret(
        name="TestSecret",
        description="TestSecret description",
    )
    rotation_policy = secret.rotation_lambda_policy
    rotation_function = PyFunction(
        name="myrotationlambda",
        description="this is a test",
        role="somearn",
        runtime="python3.9",
        code_dir="my_code_dir",
        handler="app.main",
        version=1 if alias else None,
        alias=alias,
    )
    assert rotation_function.alias is None or isinstance(rotation_function.alias, Alias)
    rotation_schedule = RotationSchedule(
        secret=secret,
        rotation_function=rotation_function,
        rotation_function_version=rotation_function.alias,
        schedule_expression="rate(4 days)",
    )
    for el in (secret, rotation_policy, rotation_function, rotation_schedule):
        stack.add(el)
    with (
        TEST_DIR
        / "secret_rotation_schedule{}.json".format(f"_{alias}" if alias else "")
    ).open() as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_secret_iam_path(stack: Stack) -> None:
    """Test Secret with iam_path."""
    secret = Secret(
        name="TestSecret",
        description="TestSecret description",
        iam_path="/iam_test_path/",
    )
    rotation_policy = secret.rotation_lambda_policy
    for el in (secret, rotation_policy):
        stack.add(el)

    with (TEST_DIR / "secret_iam_path.json").open() as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template
