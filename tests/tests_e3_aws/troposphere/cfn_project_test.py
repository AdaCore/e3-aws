"""Provide Cloudformation construct tests."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import patch
from tempfile import TemporaryDirectory
from textwrap import dedent

from e3.aws import AWSEnv
from e3.aws.troposphere import CFNProjectMain
from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere.awslambda import PyFunction
from e3.aws.mock.troposphere.awslambda import mock_pyfunctionasset


if TYPE_CHECKING:
    import pytest
    from e3.aws.cfn import Stack


TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class MyCFNProject(CFNProjectMain):
    """Provide CLI to manage MyCFNProject."""

    def create_stack(self) -> Stack | list[Stack]:
        """Return MyCFNProject stack."""
        return self.stack


class MyRoleCFNProject(CFNProjectMain):
    """Provide CLI to manage MyRoleCFNProject."""

    def create_stack(self) -> Stack | list[Stack]:
        """Return MyRoleCFNProject stack."""
        self.add(
            (
                Role(
                    name="TestRole",
                    description="TestRole description",
                    trust={"Service": "test"},
                )
            )
        )
        return self.stack


class MyPyFunctionCFNProject(CFNProjectMain):
    """Provide CLI to manage MyPyFunctionCFNProject."""

    def create_stack(self) -> Stack | list[Stack]:
        """Return MyPyFunctionCFNProject stack."""
        self.add(
            PyFunction(
                name="mypylambda",
                description="this is a test",
                role="somearn",
                runtime="python3.9",
                code_dir="my_code_dir",
                handler="app.main",
            )
        )
        return self.stack


def test_cfn_project_main(capfd: pytest.CaptureFixture[str]) -> None:
    """Test CFNProjectMain."""
    aws_env = AWSEnv(regions=["eu-west-1"], stub=True)
    test = MyRoleCFNProject(
        name="TestProject",
        account_id="12345678",
        stack_description="TestStack",
        s3_bucket="cfn-test-deploy-bucket",
        regions=["eu-west-1"],
    )
    test.execute(args=["show"], aws_env=aws_env)

    captured = capfd.readouterr()
    print(captured.out)
    with open(os.path.join(TEST_DIR, "cfn_project_test.out")) as f_out:
        assert captured.out == f_out.read()


def test_cfn_project_main_extend(capfd: pytest.CaptureFixture[str]) -> None:
    """Test adding resources with extend."""
    aws_env = AWSEnv(regions=["eu-west-1"], stub=True)
    test = MyRoleCFNProject(
        name="TestProject",
        account_id="12345678",
        stack_description="TestStack",
        s3_bucket="cfn-test-deploy-bucket",
        regions=["eu-west-1"],
    )
    test.extend(
        [
            Role(
                name="TestRoleB",
                description="TestRoleB description",
                trust={"Service": "test"},
            )
        ]
    )
    test.execute(args=["show"], aws_env=aws_env)

    captured = capfd.readouterr()
    print(captured.out)
    with open(os.path.join(TEST_DIR, "cfn_project_test_extend.out")) as f_out:
        assert captured.out == f_out.read()


@mock_pyfunctionasset()
def test_cfn_project_main_pyfunction(capfd: pytest.CaptureFixture[str]) -> None:
    """Test CFNProjectMain with a PyFunction.

    The generated template has a parameter with a default value for the S3 key
    of the PyFunctionAsset
    """
    aws_env = AWSEnv(regions=["eu-west-1"], stub=True)
    test = MyPyFunctionCFNProject(
        name="TestProject",
        account_id="12345678",
        stack_description="TestStack",
        s3_bucket="cfn-test-deploy-bucket",
        regions=["eu-west-1"],
    )
    test.execute(args=["show"], aws_env=aws_env)

    captured = capfd.readouterr()
    print(captured.out)
    with open(os.path.join(TEST_DIR, "cfn_project_test_pyfunction.out")) as f_out:
        assert captured.out == f_out.read()


def test_cfn_project_main_diff(capfd: pytest.CaptureFixture[str]) -> None:
    """Test CFNProjectMain diff."""
    # Initial stack
    test = MyCFNProject(
        name="TestProject",
        account_id="12345678",
        stack_description="TestStack",
        s3_bucket="cfn-test-deploy-bucket",
        regions=["eu-west-1"],
    )

    # Mock the response to get_template
    aws_env = AWSEnv(regions=["eu-west-1"], stub=True)
    aws_env.stub("cloudformation").add_response(
        "get_template",
        service_response={"TemplateBody": test.stack.body},
        expected_params={"StackName": "TestProject"},
    )

    # Make a change to the template
    test.add(
        Role(
            name="TestRole",
            description="TestRole description",
            trust={"Service": "test"},
        )
    )

    # It's better to disable the diff colors for tests
    def mocked_color_diff(lines: list[str]) -> list[str]:
        """Return the lines without added colors."""
        return lines

    with patch("e3.aws.cfn.main.color_diff", mocked_color_diff):
        # Diff with the mocked response
        test.execute(args=["show", "--diff"], aws_env=aws_env)

    captured = capfd.readouterr()
    print(captured.out)
    with open(os.path.join(TEST_DIR, "cfn_project_test_diff.out")) as f_out:
        assert captured.out == f_out.read()


def test_cfn_project_main_diff_assets(capfd: pytest.CaptureFixture[str]) -> None:
    """Test CFNProjectMain diff assets."""
    # Initial stack
    test = MyCFNProject(
        name="TestProject",
        account_id="12345678",
        stack_description="TestStack",
        s3_bucket="cfn-test-deploy-bucket",
        regions=["eu-west-1"],
    )

    # Mock the response to get_template
    aws_env = AWSEnv(regions=["eu-west-1"], stub=True)
    aws_env.stub("cloudformation").add_response(
        "get_template",
        service_response={"TemplateBody": test.stack.body},
        expected_params={"StackName": "TestProject"},
    )

    # Make it like no PyFunction is currently deployed
    aws_env.stub("lambda").add_client_error(
        "get_function", service_error_code="ResourceNotFoundException"
    )

    # Add a PyFunction to the template
    with TemporaryDirectory() as tmpd:
        with open(os.path.join(tmpd, "app.py"), "w"):
            pass

        test.add(
            PyFunction(
                name="mypylambda",
                description="this is a test",
                role="somearn",
                runtime="python3.9",
                code_dir=tmpd,
                handler="app.main",
            )
        )

    # It's better to disable the diff colors for tests
    def mocked_color_diff(lines: list[str]) -> list[str]:
        """Return the lines without added colors."""
        return lines

    with patch("e3.aws.troposphere.awslambda.color_diff", mocked_color_diff), patch(
        "e3.aws.cfn.main.color_diff", mocked_color_diff
    ):
        # Diff with the mocked response
        test.execute(args=["show", "--diff", "--assets"], aws_env=aws_env)

    # Only check that the diff part for the code asset of the lambda is in the output.
    # Checking the whole diff gives different results depending if we are running
    # Python < 3.14 or Python >= 3.14 https://github.com/python/cpython/pull/119492
    captured = capfd.readouterr()
    print(captured.out)
    assert (
        dedent(
            """\
            Diff for the new version of function mypylambda:
            + app.py
            """
        )
        in captured.out
    )


def test_cfn_project_main_show_assets(capfd: pytest.CaptureFixture[str]) -> None:
    """Test CFNProjectMain show assets."""
    aws_env = AWSEnv(regions=["eu-west-1"], stub=True)
    test = MyCFNProject(
        name="TestProject",
        account_id="12345678",
        stack_description="TestStack",
        s3_bucket="cfn-test-deploy-bucket",
        regions=["eu-west-1"],
    )

    # Add a PyFunction to the template
    with TemporaryDirectory() as tmpd:
        with open(os.path.join(tmpd, "app.py"), "w"):
            pass

        test.add(
            PyFunction(
                name="mypylambda",
                description="this is a test",
                role="somearn",
                runtime="python3.9",
                code_dir=tmpd,
                handler="app.main",
            )
        )

    test.execute(args=["show", "--assets"], aws_env=aws_env)

    captured = capfd.readouterr()
    print(captured.out)
    with open(os.path.join(TEST_DIR, "cfn_project_test_show_assets.out")) as f_out:
        assert captured.out == f_out.read()
