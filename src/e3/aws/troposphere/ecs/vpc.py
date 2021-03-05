"""Provide a VPC construct to run ECS tasks."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING


from troposphere import AWSObject, ec2, Ref, Tags

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack


@dataclass(frozen=True)
class EcsVPC(Construct):
    """Define a VPC for ECS tasks.

    :param name: name of the VPC
    :param region: region where to deploy the VPC
    :param cidr_block: the primary IPv4 CIDR block for the VPC
    :param subnet_cidr_block: The IPv4 CIDR block assigned to the subnet
    :param tags: the tags for the VPC
    """

    name: str
    region: str
    cidr_block: str = "10.0.0.0/16"
    subnet_cidr_block: str = "10.0.0.0/24"
    tags: dict[str, str] = field(default_factory=lambda: {})

    @property
    def vpc(self) -> ec2.VPC:
        """Return the VPC."""
        return ec2.VPC(
            name_to_id(self.name),
            CidrBlock=self.cidr_block,
            EnableDnsHostnames="true",
            EnableDnsSupport="true",
            Tags=Tags({"Name": self.name, **self.tags}),
        )

    @property
    def subnet(self) -> ec2.Subnet:
        """Return a Subnet for the VPC."""
        return ec2.Subnet(
            name_to_id(f"{self.name}Subnet"),
            VpcId=Ref(self.vpc),
            CidrBlock=self.subnet_cidr_block,
        )

    # Security group and traffic control
    @property
    def security_group(self) -> ec2.SecurityGroup:
        """Return a security group for ECS tasks."""
        return ec2.SecurityGroup(
            name_to_id(f"{self.name}SecurityGroup"),
            GroupDescription="Security group for ECS tasks",
            SecurityGroupEgress=[],
            SecurityGroupIngress=[],
            VpcId=Ref(self.vpc),
        )

    @property
    def ingress_rule(self) -> ec2.SecurityGroupIngress:
        """Return Ingress rule allowing traffic from aws VPC endpoints."""
        return ec2.SecurityGroupIngress(
            name_to_id(f"{self.name}Ingress"),
            CidrIp=self.cidr_block,
            FromPort="443",
            ToPort="443",
            IpProtocol="tcp",
            GroupId=Ref(self.security_group),
        )

    @property
    def egress_rule(self) -> ec2.SecurityGroupEgress:
        """Return egress that disables default egress Rule."""
        return ec2.SecurityGroupEgress(
            name_to_id(f"{self.name}Egress"),
            CidrIp=self.cidr_block,
            IpProtocol="-1",
            GroupId=Ref(self.security_group),
        )

    @property
    def s3_egress_rule(self) -> ec2.SecurityGroupEgress:
        """Return Egress rule allowing traffic to s3."""
        return ec2.SecurityGroupEgress(
            name_to_id(f"{self.name}S3Egress"),
            DestinationPrefixListId="pl-6da54004",
            FromPort="443",
            ToPort="443",
            IpProtocol="tcp",
            GroupId=Ref(self.security_group),
        )

    # VPC Enpoints
    @property
    def s3_route_table(self) -> ec2.RouteTable:
        """Return a route table for s3 endpoint."""
        return ec2.RouteTable(
            name_to_id(f"{self.name}S3RouteTable"), VpcId=Ref(self.vpc)
        )

    @property
    def s3_route_table_assoc(self) -> ec2.SubnetRouteTableAssociation:
        """Return route table association."""
        return ec2.SubnetRouteTableAssociation(
            name_to_id(f"{self.name}S3RouteTableAssoc"),
            RouteTableId=Ref(self.s3_route_table),
            SubnetId=Ref(self.subnet),
        )

    @property
    def s3_vpc_endpoint(self) -> ec2.VPCEndPoint:
        """Return S3 VPC Endpoint.

        Needed to retrieve images as ECR store images on S3.
        """
        return ec2.VPCEndpoint(
            name_to_id(f"{self.name}S3Endpoint"),
            PolicyDocument=self.s3_endpoint_policy_document.as_dict,
            RouteTableIds=[Ref(self.s3_route_table)],
            ServiceName=f"com.amazonaws.{self.region}.s3",
            VpcEndpointType="Gateway",
            VpcId=Ref(self.vpc),
        )

    @property
    def s3_endpoint_policy_document(self) -> PolicyDocument:
        """Return policy document for S3 endpoint."""
        return PolicyDocument(
            statements=[
                PolicyStatement(
                    action=["s3:GetObject", "s3:ListBucket"],
                    effect="Allow",
                    resource="*",
                    principal="*",
                )
            ]
        )

    @property
    def sts_vpc_endpoint(self) -> ec2.VPCEndPoint:
        """Return STS VPC Endpoint.

        Needed to initialize session from the container.
        """
        return ec2.VPCEndpoint(
            name_to_id(f"{self.name}STSEndpoint"),
            PrivateDnsEnabled="true",
            SecurityGroupIds=[Ref(self.security_group)],
            ServiceName=f"com.amazonaws.{self.region}.sts",
            SubnetIds=[Ref(self.subnet)],
            VpcEndpointType="Interface",
            VpcId=Ref(self.vpc),
        )

    @property
    def cloudwatch_logs_vpc_endpoint(self) -> ec2.VPCEndPoint:
        """Return Cloudwatch VPC Endpoint.

        Needed for ecs task to send logs to cloudwatch.
        """
        return ec2.VPCEndpoint(
            name_to_id(f"{self.name}CloudwatchLogsEndpoint"),
            PrivateDnsEnabled="true",
            SecurityGroupIds=[Ref(self.security_group)],
            ServiceName=f"com.amazonaws.{self.region}.logs",
            SubnetIds=[Ref(self.subnet)],
            VpcEndpointType="Interface",
            VpcId=Ref(self.vpc),
        )

    @property
    def ecr_dkr_vpc_endpoint(self) -> ec2.VPCEndPoint:
        """Return ECR dkr VPC Endpoint.

        Needed to retrieve images from ECR service.
        """
        return ec2.VPCEndpoint(
            name_to_id(f"{self.name}EcrDkrEndpoint"),
            PolicyDocument=self.ecr_endpoints_policy_document.as_dict,
            PrivateDnsEnabled="true",
            SecurityGroupIds=[Ref(self.security_group)],
            ServiceName=f"com.amazonaws.{self.region}.ecr.dkr",
            SubnetIds=[Ref(self.subnet)],
            VpcEndpointType="Interface",
            VpcId=Ref(self.vpc),
        )

    @property
    def ecr_api_vpc_endpoint(self) -> ec2.VPCEndPoint:
        """Return ECR api VPC Endpoint.

        Needed to retrieve images from ECR service.
        """
        return ec2.VPCEndpoint(
            name_to_id(f"{self.name}EcrApiEndpoint"),
            PolicyDocument=self.ecr_endpoints_policy_document.as_dict,
            PrivateDnsEnabled="true",
            SecurityGroupIds=[Ref(self.security_group)],
            ServiceName=f"com.amazonaws.{self.region}.ecr.api",
            SubnetIds=[Ref(self.subnet)],
            VpcEndpointType="Interface",
            VpcId=Ref(self.vpc),
        )

    @property
    def ecr_endpoints_policy_document(self) -> PolicyDocument:
        """Return policy Document for ecr endpoint allowing only image pulls."""
        return PolicyDocument(
            statements=[
                PolicyStatement(
                    action=[
                        "ecr:BatchGetImage",
                        "ecr:GetAuthorizationToken",
                        "ecr:GetDownloadUrlForLayer",
                    ],
                    effect="Allow",
                    resource="*",
                    principal="*",
                )
            ]
        )

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Construct and return EcsVPC resources."""
        return [
            self.vpc,
            self.subnet,
            self.security_group,
            self.ingress_rule,
            self.egress_rule,
            self.s3_egress_rule,
            self.s3_route_table,
            self.s3_route_table_assoc,
            self.s3_vpc_endpoint,
            self.cloudwatch_logs_vpc_endpoint,
            self.sts_vpc_endpoint,
            self.ecr_dkr_vpc_endpoint,
            self.ecr_api_vpc_endpoint,
        ]
