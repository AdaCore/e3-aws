from e3.aws.cfn.ec2 import VPC
from e3.aws.cfn.ec2.security import SecurityGroup


def test_security_group():
    vpc = VPC("vpc", cidr_block="10.10.0.0/16")
    sg = SecurityGroup("SecurityGroup",
                       vpc,
                       description="basic security group")
    assert sg.properties
