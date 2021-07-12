"""Provide AWS Config construct tests."""

from e3.aws.troposphere.config.configuration_recorder import ConfigurationRecorder
from e3.aws.troposphere.config.config_rule import (
    S3BucketPublicWriteProhibited,
    S3BucketPublicReadProhibited,
    S3BucketServerSideEncryptionEnabled,
    S3BucketSSLRequestsOnly,
    IAMUserNoPoliciesCheck,
)
from e3.aws.troposphere import Stack

EXPECTED_RULES = {
    "S3BucketPublicWriteProhibited": {
        "Properties": {
            "ConfigRuleName": "s3-bucket-public-write-prohibited",
            "Description": (
                "Checks that your S3 buckets do not allow public write access."
                "If an S3 bucket policy or bucket ACL allows public write access"
                ", the bucket is noncompliant."
            ),
            "InputParameters": {},
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
            },
        },
        "Type": "AWS::Config::ConfigRule",
        "DependsOn": "ConfigRecorder",
    },
    "S3BucketPublicReadProhibited": {
        "Properties": {
            "ConfigRuleName": "s3-bucket-public-read-prohibited",
            "Description": (
                "Checks that your S3 buckets do not allow public read access."
                "If an S3 bucket policy or bucket ACL allows public read access,"
                " the bucket is noncompliant."
            ),
            "InputParameters": {},
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED",
            },
        },
        "Type": "AWS::Config::ConfigRule",
        "DependsOn": "ConfigRecorder",
    },
    "S3BucketServerSideEncryptionEnabled": {
        "Properties": {
            "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
            "Description": (
                "Checks that your Amazon S3 bucket either has S3 default "
                "encryption enabled or that the S3 bucket policy explicitly "
                "denies put-object requests without server side encryption."
            ),
            "InputParameters": {},
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
            },
        },
        "Type": "AWS::Config::ConfigRule",
        "DependsOn": "ConfigRecorder",
    },
    "S3BucketSslRequestsOnly": {
        "Properties": {
            "ConfigRuleName": "s3-bucket-ssl-requests-only",
            "Description": (
                "Checks whether S3 buckets have policies that require requests "
                "to use Secure Socket Layer (SSL)."
            ),
            "InputParameters": {},
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "S3_BUCKET_SSL_REQUESTS_ONLY",
            },
        },
        "Type": "AWS::Config::ConfigRule",
        "DependsOn": "ConfigRecorder",
    },
    "IamUserNoPoliciesCheck": {
        "Properties": {
            "ConfigRuleName": "iam-user-no-policies-check",
            "Description": (
                "Checks that none of your IAM users have policies attached. "
                "IAM users must inherit permissions from IAM groups or roles."
            ),
            "InputParameters": {},
            "Scope": {"ComplianceResourceTypes": ["AWS::IAM::User"]},
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "IAM_USER_NO_POLICIES_CHECK",
            },
        },
        "Type": "AWS::Config::ConfigRule",
        "DependsOn": "ConfigRecorder",
    },
}

EXPECTED_RECORDER = {
    "AWSServiceRoleForConfig": {
        "Properties": {"AWSServiceName": "config.amazonaws.com"},
        "Type": "AWS::IAM::ServiceLinkedRole",
    },
    "ConfigRecorder": {
        "Properties": {
            "Name": "ConfigRecorder",
            "RecordingGroup": {
                "AllSupported": True,
                "IncludeGlobalResourceTypes": True,
            },
            "RoleARN": {
                "Fn::Join": [
                    ":",
                    [
                        "arn",
                        "aws",
                        "iam:",
                        {"Ref": "AWS::AccountId"},
                        "role/aws-service-role/config.amazonaws.com/"
                        "AWSServiceRoleForConfig",
                    ],
                ]
            },
        },
        "Type": "AWS::Config::ConfigurationRecorder",
        "DependsOn": "AWSServiceRoleForConfig",
    },
    "ConfigTestBucket": {
        "Properties": {
            "BucketName": "config-test-bucket",
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
    "ConfigTestBucketPolicy": {
        "Properties": {
            "Bucket": {"Ref": "ConfigTestBucket"},
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::config-test-bucket/*",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::config-test-bucket/*",
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
                        "Resource": "arn:aws:s3:::config-test-bucket/*",
                        "Condition": {
                            "Null": {"s3:x-amz-server-side-encryption": "true"}
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::config-test-bucket",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": {
                            "Fn::Join": [
                                "",
                                [
                                    "arn:aws:s3:::config-test-bucket",
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
    "DeliveryChannel": {
        "Properties": {
            "Name": "DeliveryChannel",
            "S3BucketName": {"Ref": "ConfigTestBucket"},
        },
        "Type": "AWS::Config::DeliveryChannel",
    },
}


def test_config_recorder(stack: Stack) -> None:
    """Test config recorder creation."""
    stack.add(ConfigurationRecorder(bucket_name="config-test-bucket"))
    assert stack.export()["Resources"] == EXPECTED_RECORDER


def test_config_rules(stack: Stack) -> None:
    """Test config rules creation."""
    for config_rule in (
        S3BucketPublicWriteProhibited,
        S3BucketPublicReadProhibited,
        S3BucketServerSideEncryptionEnabled,
        S3BucketSSLRequestsOnly,
        IAMUserNoPoliciesCheck,
    ):
        stack.add(config_rule)

    assert stack.export()["Resources"] == EXPECTED_RULES
