"""Provide S3 construct tests."""

from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws.troposphere import Stack

EXPECTED_BUCKET = {
    "TestBucket": {
        "Properties": {
            "BucketName": "test-bucket",
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
            "VersioningConfiguration": {"Status": "Enabled"},
        },
        "Type": "AWS::S3::Bucket",
    },
    "TestBucketPolicy": {
        "Properties": {
            "Bucket": {"Ref": "TestBucket"},
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                        "Condition": {
                            "StringNotEquals": {
                                "s3:x-amz-server-side-encryption": "AES256"
                            }
                        },
                    },
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                        "Condition": {
                            "Null": {"s3:x-amz-server-side-encryption": "true"}
                        },
                    },
                ],
            },
        },
        "Type": "AWS::S3::BucketPolicy",
    },
}


def test_bucket(stack: Stack) -> None:
    """Test bucket creation.

    Note that a bucket policy is also created when a Bucket is instanciated
    """
    stack.add(Bucket(name="test-bucket"))
    assert stack.export()["Resources"] == EXPECTED_BUCKET
