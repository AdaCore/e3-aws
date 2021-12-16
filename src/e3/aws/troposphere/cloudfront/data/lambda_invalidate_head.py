import boto3
import time  # noqa: F401


def handler(event, context):
    path = []
    client = boto3.client("cloudfront")  # noqa: F841
    for items in event["Records"]:
        if items["s3"]["object"]["key"] == "index.html":
            path.append("/")
        else:
            path.append("/" + items["s3"]["object"]["key"])
