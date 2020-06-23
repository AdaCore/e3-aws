from __future__ import absolute_import, division, print_function

import os

from botocore.stub import ANY
from e3.aws import AWSEnv, default_region
from e3.aws.cfn import Stack
from e3.aws.cfn.main import CFNMain

DEFAULT_S3_ANSWER = {
    "ResponseMetadata": {"HTTPStatusCode": 200, "RetryAttempts": 1},
    "ETag": '"f71dbe52628a3eeee3a77ab494817525c6"',
    "VersionId": "AQSVsaeeeeeeY1r95GEBkqOyubejeVl",
}


def test_cfn_main():
    class MyCFNMain(CFNMain):
        def create_stack(self):
            return Stack(name="teststack")

    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    with default_region("us-east-1"):
        aws_env.client("cloudformation", region="us-east-1")

        stubber = aws_env.stub("cloudformation")
        stubber.add_response("validate_template", {}, {"TemplateBody": ANY})
        stubber.add_response(
            "create_stack",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "TemplateBody": ANY,
            },
        )
        stubber.add_response("describe_stacks", {}, {"StackName": "teststack"})
        with stubber:
            m = MyCFNMain(regions=["us-east-1"])
            m.execute(args=["push", "--no-wait"], aws_env=aws_env)


def test_cfn_main_s3():
    class MyCFNMain(CFNMain):
        def create_stack(self):
            return Stack(name="teststack")

    os.mkdir("data")
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    with default_region("us-east-1"):
        aws_env.client("cloudformation", region="us-east-1")

        stubber = aws_env.stub("cloudformation")
        stubber.add_response("validate_template", {}, {"TemplateURL": ANY})
        stubber.add_response(
            "create_stack",
            {},
            {
                "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                "StackName": "teststack",
                "TemplateURL": ANY,
            },
        )
        stubber.add_response("describe_stacks", {}, {"StackName": "teststack"})

        aws_env.client("s3", region="us-east-1")
        s3_stubber = aws_env.stub("s3")
        s3_stubber.add_response(
            "put_object",
            DEFAULT_S3_ANSWER,
            {
                "Bucket": "superbucket",
                "Body": ANY,
                "Key": ANY,
                "ServerSideEncryption": "AES256",
            },
        )
        with stubber:
            with s3_stubber:
                m = MyCFNMain(
                    regions=["us-east-1"],
                    data_dir="data",
                    s3_bucket="superbucket",
                    s3_key="test_key",
                )
                m.execute(args=["push", "--no-wait"], aws_env=aws_env)
