"""Provide S3 construct tests."""

from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import Py38Function
from e3.aws.troposphere.sns import Topic

EXPECTED_TEMPLATE = {
    "TestTopic": {
        "Properties": {"TopicName": "test-topic", "Subscription": []},
        "Type": "AWS::SNS::Topic",
    },
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": "templates/mypylambda_lambda.zip",
            },
            "Timeout": 3,
            "Description": "this is a test",
            "Role": "somearn",
            "FunctionName": "mypylambda",
            "Runtime": "python3.8",
            "Handler": "app.main",
        },
        "Type": "AWS::Lambda::Function",
    },
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
            "NotificationConfiguration": {
                "LambdaConfigurations": [
                    {
                        "Event": "s3:ObjectCreated:*",
                        "Function": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
                    }
                ],
                "TopicConfigurations": [
                    {"Event": "s3:ObjectCreated:*", "Topic": {"Ref": "TestTopic"}}
                ],
            },
        },
        "Type": "AWS::S3::Bucket",
        "DependsOn": ["TestTopicPolicyTpUpload"],
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
    "MypylambdaTpUpload": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "Mypylambda"},
            "Principal": "s3.amazonaws.com",
            "SourceArn": "arn:aws:s3:::test-bucket",
            "SourceAccount": {"Ref": "AWS::AccountId"},
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestTopicPolicyTpUpload": {
        "Properties": {
            "Topics": [{"Ref": "TestTopic"}],
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "s3.amazonaws.com"},
                        "Action": "sns:Publish",
                        "Resource": {"Ref": "TestTopic"},
                        "Condition": {
                            "ArnLike": {"aws:SourceArn": "arn:aws:s3:::test-bucket"}
                        },
                    }
                ],
            },
        },
        "Type": "AWS::SNS::TopicPolicy",
    },
}


def test_bucket(stack: Stack) -> None:
    """Test bucket creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    topic_test = Topic(name="test-topic")
    lambda_test = Py38Function(
        name="mypylambda",
        description="this is a test",
        role="somearn",
        code_dir="my_code_dir",
        handler="app.main",
    )

    stack.add(topic_test)
    stack.add(lambda_test)

    bucket = Bucket(name="test-bucket")
    bucket.add_notification_configuration(
        event="s3:ObjectCreated:*", target=topic_test, permission_suffix="TpUpload"
    )
    bucket.add_notification_configuration(
        event="s3:ObjectCreated:*", target=lambda_test, permission_suffix="TpUpload"
    )
    stack.add(bucket)

    assert stack.export()["Resources"] == EXPECTED_TEMPLATE
