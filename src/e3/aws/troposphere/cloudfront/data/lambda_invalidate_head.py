"""Provide a Lambda handler to invalidate CloudFront cache on S3 events."""

import os
import time

import boto3

DISTRIBUTION_ID = os.environ["DISTRIBUTION_ID"]


def handler(event, context):
    """Handle CloudFront cache invalidation on S3 events.

    :param event: the S3 event triggering the invalidation
    :param context: the Lambda runtime context
    """
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
