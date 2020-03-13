from __future__ import absolute_import, division, print_function

from botocore.stub import ANY
from e3.aws import AWSEnv, default_region
from e3.aws.cfn.arch import Fortress
from e3.aws.cfn.iam import Allow, Policy, PolicyDocument
from e3.aws.cfn.s3 import Bucket
from e3.aws.ec2.ami import AMI


def test_create_fortress():
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
        f.add_private_server(AMI("ami-1234"), ["server1", "server2"])

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
