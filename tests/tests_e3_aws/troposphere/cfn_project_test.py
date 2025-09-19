"""Provide Cloudformation construct tests."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

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
    test = MyCFNProject(
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
    test = MyCFNProject(
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
