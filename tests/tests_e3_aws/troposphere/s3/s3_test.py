"""Provide S3 construct tests."""

from e3.aws.troposphere.s3.bucket import AWSConfigBucket, Bucket
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
                "BlockPublicAcls": "true",
                "BlockPublicPolicy": "true",
                "IgnorePublicAcls": "true",
                "RestrictPublicBuckets": "true",
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

EXPECTED_AWS_CONFIG_BUCKET = {
    "TestBucket": {
        "Properties": {
            "BucketName": "test-bucket",
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": "true",
                "BlockPublicPolicy": "true",
                "IgnorePublicAcls": "true",
                "RestrictPublicBuckets": "true",
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
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::test-bucket",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": {
                            "Fn::Join": [
                                "",
                                [
                                    "arn:aws:s3:::",
                                    "test-bucket",
                                    "/AWSLogs/",
                                    {"Ref": "AWS::AccountId"},
                                    "/Config/*",
                                ],
                            ]
                        },
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control"
                            }
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


def test_aws_config_bucket(stack: Stack) -> None:
    """Test AWS Config Bucket creation.

    Note that a bucket policy is also created when a Bucket is instanciated
    """
    stack.add(AWSConfigBucket(name="test-bucket"))
    assert stack.export()["Resources"] == EXPECTED_AWS_CONFIG_BUCKET
