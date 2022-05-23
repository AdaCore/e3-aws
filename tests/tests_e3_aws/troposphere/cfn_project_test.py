"""Provide Cloudformation construct tests."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from e3.aws import AWSEnv
from e3.aws.troposphere import CFNProjectMain
from e3.aws.troposphere.iam.role import Role


if TYPE_CHECKING:
    from e3.aws.troposphere import Stack


TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class MyCFNProject(CFNProjectMain):
    """Provide CLI to manage MyCFNProject."""

    def create_stack(self) -> list[Stack]:
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


def test_cfn_project_main(capfd) -> None:
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
