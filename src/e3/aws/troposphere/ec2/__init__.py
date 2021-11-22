from __future__ import annotations

from typing import TYPE_CHECKING

from troposphere import ec2, Ref

from e3.aws import name_to_id
from e3.aws.troposphere import Construct


if TYPE_CHECKING:
    from troposphere import AWSObject

    from e3.aws.troposphere import Stack


class InternetGateway(Construct):
    """InternetGateway construct.

    Provide an internet gateway attached to a given VPC and a route table routing
    traffic from given subnets to the gateway.
    """

    def __init__(self, name_prefix: str, vpc: ec2.vpc, subnets: list[ec2.subnet]):
        """Initialize InternetGateway construct.

        :param name_prefix: prefix for cloudformation resource names
        :param vpc: VPC to attach to InternetGateway
        :param subnets: subnets from wich traffic should be routed to the internet
            gateway.
        """
        self.vpc = vpc
        self.subnets = subnets
        self.name_prefix = name_prefix

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return resources associated with the construct."""
        igw = ec2.InternetGateway(name_to_id(f"{self.name_prefix}-igw"))
        attachement = ec2.VPCGatewayAttachment(
            name_to_id(f"{self.name_prefix}-igw-attachement"),
            InternetGatewayId=Ref(igw),
            VpcId=Ref(self.vpc),
        )
        route_table = ec2.RouteTable(
            name_to_id(f"{self.name_prefix}-igw-route-table"), VpcId=Ref(self.vpc)
        )
        route = ec2.Route(
            name_to_id(f"{self.name_prefix}-igw-route"),
            RouteTableId=Ref(route_table),
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=Ref(igw),
        )
        route_table_associations = (
            ec2.SubnetRouteTableAssociation(
                name_to_id(f"{self.name_prefix}-{num}"),
                RouteTableId=Ref(route_table),
                SubnetId=Ref(subnet),
            )
            for subnet, num in zip(self.subnets, range(len(self.subnets)))
        )
        return [igw, attachement, route_table, route, *route_table_associations]
