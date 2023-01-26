from __future__ import annotations
import pytest
import argparse
from unittest import mock
from textwrap import dedent
from botocore.credentials import ReadOnlyCredentials
from e3.aws import assume_profile_main
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


# Output expected when running without --json
EXPECTED_DEFAULT_OUTPUT = dedent(
    """\
    export AWS_ACCESS_KEY_ID=access_key
    export AWS_SECRET_ACCESS_KEY=secret_key
    export AWS_SESSION_TOKEN=token"""
)


# Output expected when running with --json
EXPECTED_JSON_OUTPUT = (
    '{"AccessKeyId": "access_key", "SecretAccessKey": '
    '"secret_key", "SessionToken": "token"}'
)


class MockSession:
    def __init__(self, *args: list[Any], **kwargs: dict[str, Any]) -> None:
        """Mock the boto3.Session class."""
        pass

    def get_credentials(self) -> "MockSession":
        """Return this class for get_frozen_credentials."""
        return self

    def get_frozen_credentials(self) -> ReadOnlyCredentials:
        """Return fake credentials."""
        return ReadOnlyCredentials("access_key", "secret_key", "token")


@pytest.mark.parametrize(
    "json,expected_output",
    [(False, EXPECTED_DEFAULT_OUTPUT), (True, EXPECTED_JSON_OUTPUT)],
)
def test_assume_profile_main_json(json: bool, expected_output: str, capfd):
    """Test the credentials returned by assume_profile_main."""
    with (
        mock.patch(
            "argparse.ArgumentParser.parse_args",
            return_value=argparse.Namespace(json=json, profile="foo"),
        ),
        mock.patch(
            "boto3.Session",
            new=MockSession,
        ),
    ):
        assume_profile_main()

    stdout = capfd.readouterr().out
    assert stdout.strip() == expected_output
