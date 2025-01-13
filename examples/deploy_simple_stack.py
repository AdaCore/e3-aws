#!/usr/bin/env python
"""Provide a Command Line Interface to manage MySimpleStack stack.

The stack consists of a VPC with private and public subnets in eu-west-1a AZ
and a NAT Gateway to route traffic from the private subnet to the Internet.
It also deploys an instance in the private subnet with its IAM profile, and
a security group.

As it relies on CFNProjectMain it requires a deployment and a
CloudFormation roles named respectively cfn-user/CFNAllowDeployOfMySimpleStack
and cfn-service/CFNServiceRoleForMySimpleStack.

The 'CFNAllow' role must be assumable by the user deploying the stack.
The 'CFNServiceRole' must trust the CloudFormation service.

For more details on how to manage the stack run:
./deploy_simple_stack.py --help
"""
from __future__ import annotations
from functools import cached_property
import sys
from typing import TYPE_CHECKING

from e3.aws.troposphere import CFNProjectMain, Construct, name_to_id, Stack
from e3.aws.troposphere.ec2 import VPCv2
from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere.iam.policy_statement import Trust
from troposphere import ec2, iam, Ref, GetAtt, Tags

if TYPE_CHECKING:
    from troposphhere import AWSObject

STACK_NAME = "MySimpleStack"
ACCOUNT_ID = "012345678910"
REGION = "eu-west-1"
AZ = "eu-west-1a"
IAM_PATH = "/my-simple-stack/"
INSTANCE_AMI = "ami-1234"

# S3 Bucket where templates are pushed for deployment
# The "CFNAllowDeployOf" role must be allowed to push files to:
# my-cfn-bucket/my-simple-stack/*
# The "CFNServiceRole" must be allowed to read files from:
# my-cfn-bucket/my-simple-stack/*
CFN_BUCKET = "my-cfn-bucket"


class SimpleInstance(Construct):
    """Provide a construct deploying a simple instance."""

    def __init__(self, name: str, vpc: VPCv2, ami: str, instance_type: str) -> None:
        """Initialize a SimpleInstance instance.

        :param name: name of the instance
        :param vpc: a vpc to host the instance
        :param ami: AMI for the instance
        :param instance_type: the EC2 instance type
        """
        self.name = name
        self.vpc = vpc
        self.ami = ami
        self.instance_type = instance_type

    @cached_property
    def role(self) -> Role:
        """Return a role for the simple instance."""
        return Role(
            name=f"{self.name}InstanceRole",
            description="Simple instance instance role",
            path=IAM_PATH,
            trust=Trust(services=["ec2"]),
            managed_policy_arns=[
                # Access to CloudWatch and SSM
                "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
                "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
                "arn:aws:iam::aws:policy/AmazonSSMPatchAssociation",
            ],
        )

    @cached_property
    def profile(self) -> iam.InstanceProfile:
        """Return an instance profile for the simple instance."""
        profile_name = f"{self.name}InstanceProfile"
        return iam.InstanceProfile(
            title=name_to_id(profile_name),
            InstanceProfileName=profile_name,
            Path=IAM_PATH,
            Roles=[self.role.name],
            DependsOn=self.role.name,
        )

    @cached_property
    def security_group(self) -> ec2.SecurityGroup:
        """Return instance security group.

        Allow no inbound and all outbound.
        """
        group_name = f"{self.name}SG"
        return ec2.SecurityGroup(
            name_to_id(group_name),
            GroupDescription=f"Security group for {self.name} instance",
            GroupName=group_name,
            SecurityGroupEgress=[
                ec2.SecurityGroupRule(CidrIp="0.0.0.0/0", IpProtocol="-1"),
                ec2.SecurityGroupRule(CidrIpv6="::/0", IpProtocol="-1"),
            ],
            SecurityGroupIngress=[],
            VpcId=Ref(self.vpc.vpc),
        )

    @cached_property
    def instance(self) -> ec2.Instance:
        """Return a simple instance."""
        return ec2.Instance(
            title=name_to_id(self.name),
            ImageId=self.ami,
            IamInstanceProfile=Ref(self.profile),
            InstanceType=self.instance_type,
            SubnetId=Ref(self.vpc.private_subnets[AZ]),
            # Use default security group that comes with the VPC
            SecurityGroupIds=[GetAtt(self.security_group, "GroupId")],
            PropagateTagsToVolumeOnCreation=True,
            BlockDeviceMappings=[
                ec2.BlockDeviceMapping(
                    Ebs=ec2.EBSBlockDevice(VolumeType="gp3", VolumeSize="20"),
                    DeviceName="/dev/sda1",
                )
            ],
            Tags=Tags({"Name": self.name}),
        )

    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
        """Return resources for this construct."""
        return [
            self.role,
            self.profile,
            self.security_group,
            self.instance,
        ]


class MySimpleStackMain(CFNProjectMain):
    """Provide CLI to manage MySimpleStack stack."""

    def create_stack(self) -> list[Stack]:
        """Create MySimpleStack stack."""
        vpc = VPCv2(
            name_prefix=self.stack.name,
            cidr_block="10.50.0.0/16",
            availability_zones=[AZ],
        )
        self.add(vpc)
        self.add(
            SimpleInstance(
                name="MySimpleInstance",
                vpc=vpc,
                ami="MYAMi-1234",
                instance_type="t4g.small",
            )
        )
        return self.stack


def main(args: list[str] | None = None) -> None:
    """Entry point.

    :param args: the list of positional parameters. If None then
        ``sys.argv[1:]`` is used
    """
    project = MySimpleStackMain(
        name=STACK_NAME,
        account_id=ACCOUNT_ID,
        stack_description="Stack deploying an instance",
        s3_bucket=f"cfn-gitlab-adacore-{REGION}",
        regions=[REGION],
    )
    sys.exit(project.execute(args))


if __name__ == "__main__":
    main()
