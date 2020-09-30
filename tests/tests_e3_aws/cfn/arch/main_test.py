from __future__ import absolute_import, division, print_function

import pytest

from botocore.stub import ANY
from e3.aws import AWSEnv, default_region
from e3.aws.cfn.arch import Fortress
from e3.aws.cfn.iam import Allow, Policy, PolicyDocument
from e3.aws.cfn.s3 import Bucket
from e3.aws.ec2.ami import AMI

AWS_IP_RANGES = {
    "syncToken": "1600978876",
    "createDate": "2020-09-24-20-21-16",
    "prefixes": [
        {
            "ip_prefix": "3.5.140.0/22",
            "region": "ap-northeast-2",
            "service": "AMAZON",
            "network_border_group": "ap-northeast-2",
        },
        {
            "ip_prefix": "120.52.22.96/27",
            "region": "GLOBAL",
            "service": "AMAZON",
            "network_border_group": "GLOBAL",
        },
        {
            "ip_prefix": "150.222.81.0/24",
            "region": "eu-west-1",
            "service": "AMAZON",
            "network_border_group": "eu-west-1",
        },
        {
            "ip_prefix": "52.4.0.0/14",
            "region": "us-east-1",
            "service": "AMAZON",
            "network_border_group": "us-east-1",
        },
    ],
}

GITHUB_API_RANGE = {"git": ["127.0.0.1/24"]}


@pytest.mark.parametrize("enable_github", [True, False])
def test_create_fortress(enable_github, requests_mock):
    if enable_github:
        requests_mock.get("https://api.github.com/meta", json=GITHUB_API_RANGE)
    requests_mock.get(
        "https://ip-ranges.amazonaws.com/ip-ranges.json", json=AWS_IP_RANGES
    )
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    with default_region("us-east-1"):
        stub = aws_env.stub("ec2", region="us-east-1")
        stub.add_response(
            "describe_images",
            {
                "Images": [
                    {"ImageId": "ami-1234", "RootDeviceName": "/dev/sda1", "Tags": []}
                ]
            },
            {"ImageIds": ANY},
        )
        stub.add_response(
            "describe_images",
            {
                "Images": [
                    {"ImageId": "ami-1234", "RootDeviceName": "/dev/sda1", "Tags": []}
                ]
            },
            {"ImageIds": ANY},
        )
        d = PolicyDocument().append(
            Allow(
                to="s3:GetObject",
                on=["arn:aws:s3:::mybucket", "arn:aws:s3:::mybucket/*"],
            )
        )
        p = Policy("InternalPolicy", d)
        f = Fortress(
            "myfortress",
            allow_ssh_from="0.0.0.0/0",
            bastion_ami=AMI("ami-1234"),
            internal_server_policy=p,
        )
        f += Bucket("Bucket2")

        # Allow access to mybucket through a s3 endpoint
        f.private_subnet.add_bucket_access(["mybucket", f["Bucket2"]])

        # allow https
        f.add_network_access("https")
        f.add_private_server(
            AMI("ami-1234"), ["server1", "server2"], github_access=enable_github
        )

        assert f.body


def test_create_fortress_no_bastion():
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    with default_region("us-east-1"):
        stub = aws_env.stub("ec2", region="us-east-1")
        stub.add_response(
            "describe_images",
            {
                "Images": [
                    {"ImageId": "ami-1234", "RootDeviceName": "/dev/sda1", "Tags": []}
                ]
            },
            {"ImageIds": ANY},
        )
        stub.add_response(
            "describe_images",
            {
                "Images": [
                    {"ImageId": "ami-1234", "RootDeviceName": "/dev/sda1", "Tags": []}
                ]
            },
            {"ImageIds": ANY},
        )
        d = PolicyDocument().append(
            Allow(
                to="s3:GetObject",
                on=["arn:aws:s3:::mybucket", "arn:aws:s3:::mybucket/*"],
            )
        )
        p = Policy("InternalPolicy", d)
        f = Fortress("myfortress", bastion_ami=None, internal_server_policy=p)
        f += Bucket("Bucket2")

        # Allow access to mybucket through a s3 endpoint
        f.private_subnet.add_bucket_access(["mybucket", f["Bucket2"]])

        # allow https
        f.add_network_access("https")
        f.add_private_server(AMI("ami-1234"), ["server1", "server2"])

        assert f.body
