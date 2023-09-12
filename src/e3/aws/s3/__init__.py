from __future__ import annotations
from typing import TYPE_CHECKING
import logging
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger("e3.aws.s3")


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

    def delete(self, key: str) -> None:
        """Delete content from S3.

        :param key: object key
        """
        self.client.delete_object(Bucket=self.bucket, Key=key)
