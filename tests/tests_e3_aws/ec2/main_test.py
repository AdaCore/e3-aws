import pytest
from e3.aws import AWSEnv, default_region, Session
from e3.aws.ec2.ami import AMI


def test_ls_ami():
    """List AMIS from all regions."""
    aws_env = AWSEnv(regions=["us-east-1", "eu-west-1"], stub=True)
    stub_us = aws_env.stub("ec2", region="us-east-1")
    stub_eu = aws_env.stub("ec2", region="eu-west-1")

    stub_eu.add_response(
        "describe_images",
        {
            "Images": [
                {"ImageId": "ami-1234", "RootDeviceName": "/dev/sda1", "Tags": []}
            ]
        },
        {"Filters": [], "Owners": ["self"]},
    )
    stub_us.add_response(
        "describe_images",
        {
            "Images": [
                {"ImageId": "ami-5678", "RootDeviceName": "/dev/sda1", "Tags": []}
            ]
        },
        {"Filters": [], "Owners": ["self"]},
    )
    assert len(AMI.ls()) == 2


def test_select():
    """Test AMI.select."""
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    stub = aws_env.stub("ec2", region="us-east-1")

    Images = {
        "Images": [
            {
                "ImageId": "ami-1",
                "RootDeviceName": "/dev/sda1",
                "Tags": [
                    {"Key": "platform", "Value": "x86_64-linux"},
                    {"Key": "os_version", "Value": "suse11"},
                    {"Key": "timestamp", "Value": "4"},
                ],
            },
            {
                "ImageId": "ami-2",
                "RootDeviceName": "/dev/sda1",
                "Tags": [
                    {"Key": "platform", "Value": "x86_64-linux"},
                    {"Key": "os_version", "Value": "suse11"},
                    {"Key": "timestamp", "Value": "5"},
                ],
            },
            {
                "ImageId": "ami-3",
                "RootDeviceName": "/dev/sda1",
                "Tags": [
                    {"Key": "platform", "Value": "x86_64-linux"},
                    {"Key": "os_version", "Value": "suse11"},
                    {"Key": "timestamp", "Value": "1"},
                ],
            },
            {
                "ImageId": "ami-4",
                "RootDeviceName": "/dev/sda1",
                "Tags": [
                    {"Key": "platform", "Value": "x86_64-linux"},
                    {"Key": "timestamp", "Value": "1"},
                ],
            },
            {
                "ImageId": "ami-1234",
                "RootDeviceName": "/dev/sda1",
                "Tags": [
                    {"Key": "platform", "Value": "x86_64-linux"},
                    {"Key": "os_version", "Value": "ubuntu16.04"},
                    {"Key": "timestamp", "Value": "1"},
                ],
            },
            {
                "ImageId": "ami-5",
                "RootDeviceName": "/dev/sda1",
                "Tags": [
                    {"Key": "platform", "Value": "x86_64-linux"},
                    {"Key": "os_version", "Value": "suse11"},
                    {"Key": "timestamp", "Value": "5"},
                    {"Key": "kind", "Value": "build"},
                ],
            },
        ]
    }

    stub.add_response(
        "describe_images",
        Images,
        {
            "Filters": [
                {"Name": "tag-key", "Values": ["platform"]},
                {"Name": "tag-key", "Values": ["timestamp"]},
                {"Name": "tag-key", "Values": ["os_version"]},
            ],
            "Owners": ["self"],
        },
    )
    stub.add_response(
        "describe_images",
        Images,
        {
            "Filters": [
                {"Name": "tag-key", "Values": ["platform"]},
                {"Name": "tag-key", "Values": ["timestamp"]},
                {"Name": "tag-key", "Values": ["os_version"]},
                {"Name": "tag-key", "Values": ["kind"]},
            ],
            "Owners": ["self"],
        },
    )

    with default_region("us-east-1"):
        ami = AMI.select(platform="x86_64-linux", os_version="suse11")
        assert ami.id == "ami-2"
        ami = AMI.select(platform="x86_64-linux", os_version="suse11", kind="build")
        assert ami.id == "ami-5"


def test_session_without_args():
    """Raise error when no arguments."""
    with pytest.raises(ValueError):
        session = Session()
        session.client("ec2")
