from __future__ import annotations
from typing import TYPE_CHECKING
import pytest
from moto import mock_sts, mock_s3
import boto3
from e3.aws.s3 import S3, KeyExistsError, KeyNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterable


@pytest.fixture
def client() -> Iterable[S3]:
    """Return a client for S3."""
    with mock_sts(), mock_s3():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="test")

        yield S3(client=client, bucket="test")


def test_push(client: S3) -> None:
    """Test pushing content."""
    client.push("foo", b"hello")

    assert client.get("foo") == b"hello"


def test_push_already_exist_ok(client: S3) -> None:
    """Test pushing content with an existing key."""
    test_push(client)
    test_push(client)


def test_push_already_exist_error(client: S3) -> None:
    """Test pushing content with an existing key."""
    test_push(client)

    with pytest.raises(KeyExistsError):
        client.push("foo", b"world", exist_ok=False)


def test_get_not_found_ok(client: S3) -> None:
    """Test getting content with a missing key."""
    assert client.get("foo", default=b"") == b""


def test_get_not_found_error(client: S3) -> None:
    """Test getting content with a missing key."""
    with pytest.raises(KeyNotFoundError):
        client.get("foo")


def test_delete(client: S3) -> None:
    """Test deleting content."""
    test_push(client)
    client.delete("foo")
    test_get_not_found_error(client)


def test_delete_missing(client: S3) -> None:
    """Test deleting content with a missing key."""
    client.delete("foo")
