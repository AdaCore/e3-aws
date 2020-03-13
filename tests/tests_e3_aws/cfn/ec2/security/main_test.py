import pytest
from e3.aws.cfn.ec2 import VPC
from e3.aws.cfn.ec2.security import EgressRule, IngressRule, SecurityGroup


def test_security_group():
    vpc = VPC("vpc", cidr_block="10.10.0.0/16")
    rule1 = IngressRule("ssh", "10.10.1.1/32", description="ssh rule")
    rule2 = IngressRule("ip", "10.10.1.1/32", from_port=3389)
    rule2 = IngressRule("ip", "10.10.1.1/32", from_port=5000, to_port=5550)
    sg = SecurityGroup(
        "SecurityGroup", vpc, description="basic security group", rules=[rule1, rule2]
    )
    assert sg.properties

    sg.add_rule(EgressRule("ip", "10.10.1.1/32", from_port=80))
    assert sg.properties

    with pytest.raises(AssertionError):
        sg.add_rule("invalid object")
