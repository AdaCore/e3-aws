import boto3
import os
import time

DISTRIBUTION_ID = os.environ["DISTRIBUTION_ID"]


def handler(event, context):
    path = []
    client = boto3.client("cloudfront")  # noqa: F841
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
