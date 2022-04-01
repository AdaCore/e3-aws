"""Provide InternetGateway construct tests."""

from __future__ import annotations

import pytest
from troposphere import ec2, Ref

from e3.aws import name_to_id
from e3.aws.troposphere import Stack
from e3.aws.troposphere.ec2 import InternetGateway


EXPECTED_TEMPLATE = {
    "VpcTest": {
        "Properties": {
            "CidrBlock": "10.0.0.0/16",
            "EnableDnsHostnames": True,
            "EnableDnsSupport": True,
        },
        "Type": "AWS::EC2::VPC",
    },
    "EuWest1aSubnet": {
        "Properties": {
            "CidrBlock": "10.0.0.0/20",
            "AvailabilityZone": "eu-west-1b",
            "VpcId": {"Ref": "VpcTest"},
            "MapPublicIpOnLaunch": True,
        },
        "Type": "AWS::EC2::Subnet",
    },
    "EuWest1bSubnet": {
        "Properties": {
            "CidrBlock": "10.0.0.0/20",
            "AvailabilityZone": "eu-west-1b",
            "VpcId": {"Ref": "VpcTest"},
            "MapPublicIpOnLaunch": True,
        },
        "Type": "AWS::EC2::Subnet",
    },
    "TestIgw": {"Type": "AWS::EC2::InternetGateway"},
    "TestIgwAttachement": {
        "Properties": {
            "InternetGatewayId": {"Ref": "TestIgw"},
            "VpcId": {"Ref": "VpcTest"},
        },
        "Type": "AWS::EC2::VPCGatewayAttachment",
    },
    "TestIgwRoute": {
        "Properties": {
            "RouteTableId": {"Ref": "TestIgwRouteTable"},
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": {"Ref": "TestIgw"},
        },
        "Type": "AWS::EC2::Route",
    },
}


@pytest.mark.parametrize("route_table_provided", [False, True])
def test_internet_gateway(stack: Stack, route_table_provided: bool) -> None:
    """Test InternetGateway construct."""
    vpc = ec2.VPC(
        name_to_id("vpc-test"),
        CidrBlock="10.0.0.0/16",
        EnableDnsHostnames="true",
        EnableDnsSupport="true",
    )

    subnets = [
        ec2.Subnet(
            name_to_id(f"{zone}-subnet"),
            CidrBlock="10.0.0.0/20",
            AvailabilityZone="eu-west-1b",
            VpcId=Ref(vpc),
            MapPublicIpOnLaunch="true",
        )
        for zone, ip in zip(
            ["eu-west-1a", "eu-west-1b"], ["10.0.0.0/20", "10.0.16.0/20"]
        )
    ]

    if route_table_provided:
        route_table = ec2.RouteTable(name_to_id("TestIgwRouteTable"), VpcId=Ref(vpc))
    else:
        route_table = None

    igw = InternetGateway(
        name_prefix="test", vpc=vpc, subnets=subnets, route_table=route_table
    )

    for el in (vpc, *subnets, igw):
        stack.add(el)

    template = dict(EXPECTED_TEMPLATE)

    if not route_table_provided:
        template["TestIgwRouteTable"] = {
            "Properties": {"VpcId": {"Ref": "VpcTest"}},
            "Type": "AWS::EC2::RouteTable",
        }
        template["Test0"] = {
            "Properties": {
                "RouteTableId": {"Ref": "TestIgwRouteTable"},
                "SubnetId": {"Ref": "EuWest1aSubnet"},
            },
            "Type": "AWS::EC2::SubnetRouteTableAssociation",
        }
        template["Test1"] = {
            "Properties": {
                "RouteTableId": {"Ref": "TestIgwRouteTable"},
                "SubnetId": {"Ref": "EuWest1bSubnet"},
            },
            "Type": "AWS::EC2::SubnetRouteTableAssociation",
        }

    assert stack.export()["Resources"] == template
