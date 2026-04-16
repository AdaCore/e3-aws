"""Provide a Lambda handler to invalidate CloudFront cache on S3 events."""

from __future__ import annotations

import os
import time

import boto3

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

DISTRIBUTION_ID = os.environ["DISTRIBUTION_ID"]


def handler(event: dict[str, Any], context: object) -> None:
    """Handle CloudFront cache invalidation on S3 events.

    :param event: the S3 event triggering the invalidation
    :param context: the Lambda runtime context
    """
    del context
    path = []
    client = boto3.client("cloudfront")
    for items in event["Records"]:
        if items["s3"]["object"]["key"] == "index.html":
            path.append("/")
        else:
            path.append("/" + items["s3"]["object"]["key"])
    client.create_invalidation(
        DistributionId=DISTRIBUTION_ID,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": path},
            "CallerReference": str(time.time()),
        },
    )
