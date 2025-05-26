from __future__ import annotations
from typing import TYPE_CHECKING
import pytest
from unittest.mock import ANY
from moto import mock_aws
import boto3
from e3.aws import s3
from e3.aws.s3 import S3, BucketExistsError, KeyExistsError, KeyNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterable


@pytest.fixture
def client() -> Iterable[S3]:
    """Return a client for S3."""
    with mock_aws():
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


def test_iterate(client: S3) -> None:
    """Test iterating content."""
    client.push("hello", b"hello")
    client.push("prefix/world", b"world")
    assert list(client.iterate()) == [
        {
            "ChecksumAlgorithm": ANY,
            "ETag": ANY,
            "Key": "hello",
            "LastModified": ANY,
            "Size": 5,
            "StorageClass": "STANDARD",
        },
        {
            "ChecksumAlgorithm": ANY,
            "ETag": ANY,
            "Key": "prefix/world",
            "LastModified": ANY,
            "Size": 5,
            "StorageClass": ANY,
        },
    ]


def test_iterate_prefix(client: S3) -> None:
    """Test iterating content with a prefix."""
    client.push("hello", b"hello")
    client.push("prefix/world", b"world")
    assert list(client.iterate(prefix="prefix")) == [
        {
            "ChecksumAlgorithm": ANY,
            "ETag": ANY,
            "Key": "prefix/world",
            "LastModified": ANY,
            "Size": 5,
            "StorageClass": ANY,
        }
    ]


def test_delete(client: S3) -> None:
    """Test deleting content."""
    test_push(client)
    client.delete("foo")
    test_get_not_found_error(client)


def test_delete_missing(client: S3) -> None:
    """Test deleting content with a missing key."""
    client.delete("foo")


@mock_aws
def test_bucket() -> None:
    """Test creating a bucket in a context."""
    with s3.bucket("test", region="eu-west-1") as client:
        # Bucket should have been created
        assert client.bucket_exists
        assert client.key_count == 0
        client.push("foo", b"hello")
        assert client.key_count == 1

    # Bucket should still exist
    assert client.bucket_exists
    assert client.get("foo") == b"hello"


@mock_aws
def test_bucket_auto_delete() -> None:
    """Test auto bucket deletion in a context."""
    with s3.bucket("test", region="eu-west-1", auto_delete=True) as client:
        # Bucket should have been created
        assert client.bucket_exists
        assert client.key_count == 0
        client.push("foo", b"hello")
        assert client.key_count == 1

    # Bucket should no longer exist
    assert not client.bucket_exists


def test_bucket_already_exist_error(client: S3) -> None:
    """Test creating an already existing bucket in a context."""
    with pytest.raises(BucketExistsError):
        with s3.bucket("test", region="eu-west-1", exist_ok=False) as client:
            assert client.bucket_exists
