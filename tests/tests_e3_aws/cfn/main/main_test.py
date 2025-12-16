from __future__ import annotations, absolute_import, division, print_function

from datetime import datetime
import os
import pytest
import textwrap
from typing import TYPE_CHECKING

from botocore.stub import ANY
from e3.mock.os.process import mock_run, CommandResult
from e3.os.process import which
from e3.aws import AWSEnv, default_region
from e3.aws.cfn import Stack
from e3.aws.cfn.main import CFNMain

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch
    from _pytest.capture import CaptureFixture


DEFAULT_S3_ANSWER = {
    "ResponseMetadata": {"HTTPStatusCode": 200, "RetryAttempts": 1},
    "ETag": '"f71dbe52628a3eeee3a77ab494817525c6"',
    "VersionId": "AQSVsaeeeeeeY1r95GEBkqOyubejeVl",
}


def test_cfn_main() -> None:
    class MyCFNMain(CFNMain):
        def create_stack(self) -> Stack:
            return Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    with default_region("us-east-1"):
        aws_env.client("cloudformation", region="us-east-1")

        stubber = aws_env.stub("cloudformation")
        stubber.add_response("validate_template", {}, {"TemplateBody": ANY})
        stubber.add_response(
            "create_stack",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "ClientRequestToken": ANY,
                "TemplateBody": ANY,
            },
        )
        stubber.add_response("describe_stacks", {}, {"StackName": "teststack"})
        with stubber:
            m = MyCFNMain(regions=["us-east-1"])
            m.execute(args=["push", "--no-wait"], aws_env=aws_env)


def test_cfn_main_multiple_stacks() -> None:
    class MyCFNMain(CFNMain):
        def create_stack(self) -> list[Stack]:
            return [Stack(name="first-stack"), Stack(name="second-stack")]

    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    with default_region("us-east-1"):
        aws_env.client("cloudformation", region="us-east-1")

        stubber = aws_env.stub("cloudformation")
        for stack_name in ("first-stack", "second-stack"):
            stubber.add_response("validate_template", {}, {"TemplateBody": ANY})
            stubber.add_response(
                "create_stack",
                {},
                {
                    "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                    "StackName": f"{stack_name}",
                    "ClientRequestToken": ANY,
                    "TemplateBody": ANY,
                },
            )
        with stubber:
            m = MyCFNMain(regions=["us-east-1"])
            m.execute(args=["push", "--no-wait"], aws_env=aws_env)


@pytest.mark.parametrize(
    "status",
    [
        ("NOT_FAILED", "Other Reason", 0),
        (
            "FAILED",
            (
                "The submitted information didn't contain changes."
                "Submit different information to create a change set."
            ),
            0,
        ),
        ("FAILED", "Other Reason", 1),
    ],
)
def test_cfn_main_push_existing_stack(
    status: tuple[str, str, int], monkeypatch: MonkeyPatch
) -> None:
    """Test pushing an already existing stack.

    :param status: Tuple with status and status reason from describe_change_set
        response and associated expected execute return value.
    """

    class MyCFNMain(CFNMain):
        def create_stack(self):
            return [Stack(name="existing-stack")]

    aws_env = AWSEnv(regions=["us-east-1"], stub=True)

    with default_region("us-east-1"):
        aws_env.client("cloudformation", region="us-east-1")

        stack_name = "existing-stack"
        stubber = aws_env.stub("cloudformation")
        stubber.add_response("validate_template", {}, {"TemplateBody": ANY})
        stubber.add_response(
            "describe_stacks",
            service_response={
                "Stacks": [
                    {
                        "StackName": stack_name,
                        "CreationTime": datetime(2016, 1, 20, 22, 9),
                        "StackStatus": "CREATE_COMPLETE",
                        "StackId": stack_name + "1",
                    }
                ]
            },
            expected_params={"StackName": stack_name},
        )
        stubber.add_response(
            "create_change_set",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "ChangeSetName": ANY,
                "StackName": stack_name,
                "TemplateBody": ANY,
            },
        )
        stubber = stubber
        stubber.add_response(
            "describe_change_set",
            {
                "StackName": stack_name,
                "Status": status[0],
                "StatusReason": status[1],
                "Changes": [],
            },
            {"ChangeSetName": ANY, "StackName": stack_name},
        )

        if status[0] == "FAILED":
            stubber.add_response(
                "delete_change_set", {}, {"ChangeSetName": ANY, "StackName": stack_name}
            )
        else:
            stubber.add_response(
                "execute_change_set",
                {},
                {"ChangeSetName": ANY, "StackName": ANY, "ClientRequestToken": ANY},
            )
            stubber.add_response(
                "describe_stacks",
                service_response={
                    "Stacks": [
                        {
                            "StackName": stack_name,
                            "CreationTime": datetime(2016, 1, 20, 22, 9),
                            "StackStatus": "UPDATE_COMPLETE",
                            "StackId": stack_name + "1",
                        }
                    ]
                },
                expected_params={"StackName": ANY},
            )
            monkeypatch.setattr("builtins.input", lambda _: "Y")

        with stubber:
            m = MyCFNMain(regions=["us-east-1"])
            assert m.execute(args=["update", "--no-wait"], aws_env=aws_env) == status[2]


def test_cfn_main_s3() -> None:
    class MyCFNMain(CFNMain):
        def create_stack(self) -> Stack:
            return Stack(name="teststack")

    os.mkdir("data")
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    with default_region("us-east-1"):
        aws_env.client("cloudformation", region="us-east-1")

        stubber = aws_env.stub("cloudformation")
        stubber.add_response("validate_template", {}, {"TemplateURL": ANY})
        stubber.add_response(
            "create_stack",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "ClientRequestToken": ANY,
                "TemplateURL": ANY,
            },
        )
        stubber.add_response("describe_stacks", {}, {"StackName": "teststack"})

        aws_env.client("s3", region="us-east-1")
        s3_stubber = aws_env.stub("s3")
        s3_stubber.add_response(
            "put_object",
            DEFAULT_S3_ANSWER,
            {
                "Bucket": "superbucket",
                "Body": ANY,
                "Key": ANY,
                "ServerSideEncryption": "AES256",
            },
        )
        with stubber:
            with s3_stubber:
                m = MyCFNMain(
                    regions=["us-east-1"],
                    data_dir="data",
                    s3_bucket="superbucket",
                    s3_key="test_key",
                )
                m.execute(args=["push", "--no-wait"], aws_env=aws_env)


def test_cfn_local_changes_check_ko(
    capfd: CaptureFixture, monkeypatch: MonkeyPatch
) -> None:
    class MyCFNMain(CFNMain):
        def create_stack(self) -> Stack:
            return Stack(name="teststack")

    git_path = which("git", default="/usr/bin/git")
    with mock_run(
        config={
            "results": [
                # Make CFNMain think we are on main
                CommandResult(
                    cmd=[
                        git_path,
                        "-c",
                        "fetch.prune=false",
                        "branch",
                        "--show-current",
                    ],
                    raw_out=b"main",
                ),
                # Make CFNMain detect some local changes
                CommandResult(
                    cmd=[
                        git_path,
                        "-c",
                        "fetch.prune=false",
                        "status",
                        "-s",
                    ],
                    raw_out=b"?? untracked_file.txt",
                ),
            ]
        }
    ):
        # Activate the local checks
        monkeypatch.setenv("CI", "false")

        m = MyCFNMain(regions=["us-east-1"])
        assert m.execute(args=["push", "--no-wait"]) == 1

    assert "Can only deploy from a clean repository" in capfd.readouterr().out


def test_cfn_correct_branch_check_ko(
    capfd: CaptureFixture, monkeypatch: MonkeyPatch
) -> None:
    class MyCFNMain(CFNMain):
        def create_stack(self) -> Stack:
            return Stack(name="teststack")

    git_path = which("git", default="/usr/bin/git")
    with mock_run(
        config={
            "results": [
                # Make CFNMain detect an incorrect branch
                CommandResult(
                    cmd=[
                        git_path,
                        "-c",
                        "fetch.prune=false",
                        "branch",
                        "--show-current",
                    ],
                    raw_out=b"feat",
                )
            ]
        }
    ):
        # Activate the local checks
        monkeypatch.setenv("CI", "false")

        m = MyCFNMain(regions=["us-east-1"], deploy_branch="main")
        assert m.execute(args=["push", "--no-wait"]) == 1

    assert "Can only deploy from branch main" in capfd.readouterr().out


@pytest.mark.parametrize(
    "fetch_out, expected_status",
    [
        # No commit present on the remote branch
        (
            textwrap.dedent(
                """\
                From ssh.gitlab.com:e3-aws
                * branch      main -> FETCH_HEAD
                """
            ),
            0,
        ),
        # One commit present on the remote branch
        (
            textwrap.dedent(
                """\
                From ssh.gitlab.com:e3-aws
                * branch      main -> FETCH_HEAD
                  abcd..efgh  main -> origin/main
                """
            ),
            1,
        ),
    ],
)
def test_cfn_branch_up_to_date_check(
    fetch_out: str,
    expected_status: int,
    capfd: CaptureFixture,
    monkeypatch: MonkeyPatch,
) -> None:
    """Test the branch up to date check.

    :param fetch_out: output returned by git fetch
    :param expected_status: expected CFNMain exit status
    """

    class MyCFNMain(CFNMain):
        def create_stack(self) -> Stack:
            return Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    aws_env.client("cloudformation", region="us-east-1")

    stubber = aws_env.stub("cloudformation")
    stubber.add_response("validate_template", {}, {"TemplateBody": ANY})
    stubber.add_response(
        "create_stack",
        {},
        {
            "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            "StackName": "teststack",
            "ClientRequestToken": ANY,
            "TemplateBody": ANY,
        },
    )
    stubber.add_response("describe_stacks", {}, {"StackName": "teststack"})

    git_path = which("git", default="/usr/bin/git")
    with default_region("us-east-1"), stubber, mock_run(
        config={
            "results": [
                # Make CFNMain think we are on main
                CommandResult(
                    cmd=[
                        git_path,
                        "-c",
                        "fetch.prune=false",
                        "branch",
                        "--show-current",
                    ],
                    raw_out=b"main",
                ),
                # Make CFNMain detect no local changes
                CommandResult(
                    cmd=[
                        git_path,
                        "-c",
                        "fetch.prune=false",
                        "status",
                        "-s",
                    ]
                ),
                # Make CFNMain detect an outdated branch
                CommandResult(
                    cmd=[
                        git_path,
                        "-c",
                        "fetch.prune=false",
                        "fetch",
                        "origin",
                        "main",
                        "--dry-run",
                    ],
                    raw_out=fetch_out.encode(),
                ),
            ]
        }
    ):
        # Activate the local checks
        monkeypatch.setenv("CI", "false")

        m = MyCFNMain(regions=["us-east-1"], deploy_branch="main")
        assert m.execute(args=["push", "--no-wait"], aws_env=aws_env) == expected_status

    if expected_status != 0:
        assert "Can only deploy from up to date branch" in capfd.readouterr().out
