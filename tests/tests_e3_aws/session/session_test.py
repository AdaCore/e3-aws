from __future__ import annotations
import pytest

from e3.aws import AWSEnv, AWSSessionRunError
from e3.aws import Session
from datetime import datetime

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _pytest.capture import CaptureFixture


def test_run(capfd: CaptureFixture) -> None:
    """Test AWS session run method."""
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    stubber = aws_env.stub("sts")

    # 2 calls to cli_cmd are made in this test
    for _ in range(2):
        stubber.add_response(
            "assume_role",
            {
                "Credentials": {
                    "AccessKeyId": "12345678912345678",
                    "SecretAccessKey": "12345678912345678",
                    "SessionToken": "12345678912345678",
                    "Expiration": datetime(4042, 1, 1),
                }
            },
            {
                "RoleArn": "arn:aws:iam::123456789123:role/TestRole",
                "RoleSessionName": "aws_run_session",
                "DurationSeconds": 7200,
            },
        )

    with stubber:
        p_right = aws_env.run(
            ["aws", "--version"],
            "arn:aws:iam::123456789123:role/TestRole",
            output=None,
            session_duration=7200,
        )
        assert p_right.status == 0
        captured = capfd.readouterr()
        assert captured.out.startswith("aws-cli/")

        with pytest.raises(AWSSessionRunError):
            p_wrong = aws_env.run(
                ["aws", "not_a_command"],
                "arn:aws:iam::123456789123:role/TestRole",
                output=None,
                session_duration=7200,
            )
            assert p_wrong.status != 0


def test_boto3() -> None:
    """Test boto3 session from Session."""
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    stubber = aws_env.stub("sts")

    with stubber:
        session = Session(
            regions=["us-east-1"],
            credentials={
                "AccessKeyId": "AK_test",
                "SecretAccessKey": "SA_test",
                "SessionToken": "ST_test",
            },
        )
        boto3_session = session.to_boto3()
        boto3_creds = boto3_session.get_credentials().get_frozen_credentials()

        assert boto3_creds.access_key == "AK_test"
        assert boto3_creds.secret_key == "SA_test"
        assert boto3_creds.token == "ST_test"
