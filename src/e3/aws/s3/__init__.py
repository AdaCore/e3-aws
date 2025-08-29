from __future__ import annotations
from typing import TYPE_CHECKING
import os
import logging
from botocore.exceptions import ClientError
from contextlib import contextmanager
import botocore
import boto3

if TYPE_CHECKING:
    from typing import Any
    from collections.abc import Iterable, Iterator

logger = logging.getLogger("e3.aws.s3")


class BucketExistsError(Exception):
    """Exception when a bucket already exists."""

    def __init__(self, bucket: str) -> None:
        """Initialize BucketExistsError.

        :param bucket: name of the bucket
        """
        self.bucket = bucket


class KeyExistsError(Exception):
    """Exception when a key already exists."""

    def __init__(self, key: str) -> None:
        """Initialize KeyExistsError.

        :param key: key in the S3 bucket
        """
        self.key = key


class KeyNotFoundError(Exception):
    """Exception when a key doesn't exist."""

    def __init__(self, key: str) -> None:
        """Initialize KeyNotFoundError.

        :param key: key in the S3 bucket
        """
        self.key = key


class S3:
    """S3 abstraction."""

    def __init__(
        self,
        client: Any,
        bucket: str,
    ) -> None:
        """Initialize S3.

        :param client: a client for the S3 API
        :param bucket: name of the bucket
        """
        self.client = client
        self.bucket = bucket

    def create_bucket(self, *, exist_ok: bool = True) -> None:
        """Create the bucket.

        :param exist_ok: don't raise an exception if the bucket already exists
        :raises BucketExistsError: if the bucket already exists
        """
        try:
            params: dict[str, Any] = {}

            # us-east-1 is the default location
            region = self.client.meta.region_name
            if region != "us-east-1":
                params["CreateBucketConfiguration"] = {"LocationConstraint": region}

            self.client.create_bucket(Bucket=self.bucket, **params)
        except ClientError as error:
            # Raise any non already exists error
            if error.response["Error"]["Code"] not in [
                "BucketAlreadyExists",
                "BucketAlreadyOwnedByYou",
            ]:
                raise

            if not exist_ok:
                raise BucketExistsError(self.bucket) from error

    def clear_bucket(self) -> None:
        """Clear objects from S3."""
        for obj in list(self.iterate()):
            self.client.delete_object(Bucket=self.bucket, Key=obj["Key"])

    def delete_bucket(self) -> None:
        """Clear and delete the bucket."""
        self.clear_bucket()
        self.client.delete_bucket(Bucket=self.bucket)

    def push(self, key: str, content: bytes, exist_ok: bool | None = None) -> None:
        """Push content to S3.

        You can set exist_ok to false to prevent the object from being
        pushed to S3 if the key already exists.

        :param key: object key
        :param content: content to store
        :param exist_ok: if it should fail when the object already exists
        :raises KeyExistsError: if the key already exists
        """
        exist_ok = exist_ok if exist_ok is not None else True

        # Try retrieve the object if exist_ok is false
        result = (
            self.client.list_objects_v2(Bucket=self.bucket, Prefix=key)
            if not exist_ok
            else {"Contents": []}
        )
        if not result.get("Contents", []):
            self.client.put_object(
                Body=content, Bucket=self.bucket, Key=key, ServerSideEncryption="AES256"
            )
        else:
            raise KeyExistsError(key)

    def get(self, key: str, default: bytes | None = None) -> bytes:
        """Get content from S3.

        If default is None, an exception will be raised if the key
        doesn't exist in the S3 bucket.

        :param key: object key
        :raises KeyNotFoundError: the key doesn't exist
        """
        try:
            return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except ClientError as e:
            # Handle the error when key doesn't exist
            if e.response["Error"]["Code"] == "NoSuchKey":
                if default is not None:
                    return default

                raise KeyNotFoundError(key) from e
            raise e

    def iterate(self, *, prefix: str | None = None) -> Iterable[dict[str, Any]]:
        """Iterate all objects from S3.

        :param prefix: limit to objects with that prefix
        :return: an iterator over objects from S3
        """
        params = {"Bucket": self.bucket}

        if prefix is not None:
            params["Prefix"] = prefix

        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(**params):
            for content in page.get("Contents", []):
                yield content

    def delete(self, key: str) -> None:
        """Delete content from S3.

        :param key: object key
        """
        self.client.delete_object(Bucket=self.bucket, Key=key)

    @property
    def bucket_exists(self) -> bool:
        """Return if the bucket exists."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise

    def object_exists(self, key: str, /, ignore_error_403: bool = False) -> bool:
        """Check if an object exists.

        :param key: object key
        :param ignore_error_403: boto3.head_object returns a 403 error when the
            object doesn't exist and the IAM role doesn't have the s3:ListBucket
            permission. Setting ignore_error_403=True makes the function return
            False instead of raising a ClientError
        :return: if the object exists
        :raises ClientError: in case of error, or in case of permission issue
            when the object doesn't exist, the IAM role doesn't have the
            s3:ListBucket permission, and ignore_error_403 is False
        """
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "404" or (error_code == "403" and ignore_error_403):
                return False
            raise

    @property
    def key_count(self) -> int:
        """Return the number of keys from S3."""
        return len(list(self.iterate()))


@contextmanager
def bucket(
    name: str,
    *,
    client: botocore.client.S3 | None = None,
    region: str | None = None,
    auto_create: bool = True,
    auto_delete: bool = False,
    exist_ok: bool = True,
) -> Iterator[S3]:
    """Context manager to create and make AWS API calls on a bucket.

    If auto_create is True, the bucket is created when entering the
    context. If the bucket already exists and exist_ok is False, an
    exception is raised.

    If auto_delete is True, the bucket is cleared and deleted when
    leaving the context.

    :param name: name of the bucket
    :param client: a client for the S3 API
    :param region: region of the client (default AWS_DEFAULT_REGION)
    :param auto_create: create the bucket when entering the context
    :param auto_delete: delete the bucket when leaving the context
    :param exist_ok: don't raise an exception if the bucket already exists
    :raises BucketExistsError: if the bucket already exists
    """
    if client is None:
        region = region if region is not None else os.environ["AWS_DEFAULT_REGION"]
        client = boto3.client("s3", region_name=region)

    s3 = S3(client=client, bucket=name)

    if auto_create:
        s3.create_bucket(exist_ok=exist_ok)

    try:
        yield s3
    finally:
        if auto_delete:
            s3.delete_bucket()
