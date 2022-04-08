from __future__ import annotations
from typing import TYPE_CHECKING

from troposphere import ec2, GetAtt, Ref, Tags

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument

if TYPE_CHECKING:
    from typing import Optional, Tuple

    from troposphere import AWSObject
    from e3.aws.troposphere import Stack


class InternetGateway(Construct):
    """InternetGateway construct.

    Provide an internet gateway attached to a given VPC and a route table routing
    traffic from given subnets to the gateway.
    """

    def __init__(
        self,
        name_prefix: str,
        vpc: ec2.vpc,
        subnets: Optional[list[ec2.subnet]] = None,
        route_table: Optional[ec2.RouteTable] = None,
    ):
        """Initialize InternetGateway construct.

        :param name_prefix: prefix for cloudformation resource names
        :param vpc: VPC to attach to InternetGateway
        :param subnets: subnets from wich traffic should be routed to the internet
            gateway. Only needed if a route table is not provided. If provided a
            route table is created and associated to these subnets.
        :param route_table: Add route to internet gateway to this route. If no
            route is provided, one is created.
        """
        self.vpc = vpc
        self.subnets = subnets
        self.name_prefix = name_prefix
        self._route_table = route_table
        self.add_route_table_to_stack = route_table is None

    @property
    def route_table(self):
        """Return route table to which the route to IGW is added."""
        if self._route_table is None:
            self._route_table = ec2.RouteTable(
                name_to_id(f"{self.name_prefix}-igw-route-table"), VpcId=Ref(self.vpc)
            )
        return self._route_table

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return resources associated with the construct."""
        igw = ec2.InternetGateway(name_to_id(f"{self.name_prefix}-igw"))
        attachement = ec2.VPCGatewayAttachment(
            name_to_id(f"{self.name_prefix}-igw-attachement"),
            InternetGatewayId=Ref(igw),
            VpcId=Ref(self.vpc),
        )
        route = ec2.Route(
            name_to_id(f"{self.name_prefix}-igw-route"),
            RouteTableId=Ref(self.route_table),
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=Ref(igw),
        )
        result = [igw, attachement, route]

        # If a new route table has to be created associate it with provided subnets
        if self.add_route_table_to_stack:
            result.append(self.route_table)
            assert self.subnets is not None
            result.extend(
                [
                    ec2.SubnetRouteTableAssociation(
                        name_to_id(f"{self.name_prefix}-{num}"),
                        RouteTableId=Ref(self.route_table),
                        SubnetId=Ref(subnet),
                    )
                    for subnet, num in zip(self.subnets, range(len(self.subnets)))
                ]
            )

        return result


class VPCEndpointsSubnet(Construct):
    """VPCEndpointsSubnet Construct.

    Provide a subnet with Interface VPC endpoints and a security group
    configured to authorize access to endpoints from given security groups.
    """

    def __init__(
        self,
        name: str,
        region: str,
        cidr_block: str,
        vpc: ec2.vpc,
        authorized_sgs: list[ec2.SecurityGroup],
        interface_endpoints: Optional[
            list[Tuple[str, Optional[PolicyDocument]]]
        ] = None,
    ) -> None:
        """Initialize VPCEndpointsSubnet Construct.

        :param name: name of the subnet
        :param region: AWS region where to deploy the Subnet
        :param vpc_endpoint_cidr_block: The IPv4 CIDR block assigned to the subnet
        :param vpc: attach the subnet to this vpc
        :param authorized_sgs: security groups authorized to access this subnet's
            endpoints
        :param interface_endpoint: list of (<service_name>, <endpoint_policy_document>)
            tuples for each interface endpoint to create in the vpc endpoints subnet.
        """
        self.name = name
        self.region = region
        self.cidr_block = cidr_block
        self.vpc = vpc
        self.authorized_sgs = authorized_sgs

        if interface_endpoints:
            self.interface_endpoints = interface_endpoints
        else:
            self.interface_endpoints = []

        self._subnet: Optional[ec2.Subnet] = None
        self._security_group: Optional[ec2.SecurityGroup] = None

    @property
    def subnet(self) -> ec2.Subnet:
        """Return a Subnet for VPC endpoints."""
        if self._subnet is None:
            subnet_name = f"{self.name}Subnet"
            self._subnet = ec2.Subnet(
                name_to_id(subnet_name),
                VpcId=Ref(self.vpc),
                CidrBlock=self.cidr_block,
                Tags=Tags({"Name": subnet_name}),
            )
        return self._subnet

    @property
    def security_group(self) -> ec2.SecurityGroup:
        """Return a security group for VPC endpoints."""
        if self._security_group is None:
            self._security_group = ec2.SecurityGroup(
                name_to_id(f"{self.name}SecurityGroup"),
                GroupDescription=f"{self.name} vpc endpoints security group",
                SecurityGroupEgress=[],
                SecurityGroupIngress=[],
                VpcId=Ref(self.vpc),
            )
        return self._security_group

    def https_ingress_rule(
        self, security_group: ec2.SecurityGroup
    ) -> ec2.SecurityGroupIngress:
        """Return Ingress rule allowing HTTPS traffic from a given security group.

        :param security_group: authorize https inbound access from this sg.
        """
        return ec2.SecurityGroupIngress(
            name_to_id(f"{self.name}Ingress{security_group.title}"),
            SourceSecurityGroupId=Ref(security_group),
            FromPort="443",
            ToPort="443",
            IpProtocol="tcp",
            GroupId=Ref(self.security_group),
        )

    def https_egress_rule(
        self, security_group: ec2.SecurityGroup
    ) -> ec2.SecurityGroupEgress:
        """Return Egress rule allowing HTTPS traffic to a given security group.

        :param security_group: authorize https outbound access to this sg.
        """
        return ec2.SecurityGroupEgress(
            name_to_id(f"{self.name}Egress{security_group.title}"),
            DestinationSecurityGroupId=Ref(security_group),
            FromPort="443",
            ToPort="443",
            IpProtocol="tcp",
            GroupId=Ref(self.security_group),
        )

    @property
    def default_egress_rule(self) -> ec2.SecurityGroupEgress:
        """Return egress that disables default egress Rule."""
        return ec2.SecurityGroupEgress(
            name_to_id(f"{self.name}DefaultEgress"),
            CidrIp=self.cidr_block,
            IpProtocol="-1",
            GroupId=Ref(self.security_group),
        )

    @property
    def interface_vpc_endpoints(self) -> list[ec2.VPCEndpoint]:
        """Return interface endpoints."""
        endpoints = []

        for service_name, pd in self.interface_endpoints:

            if pd is not None:
                opt_params = {"PolicyDocument": pd.as_dict}
            else:
                opt_params = {}
            endpoints.append(
                ec2.VPCEndpoint(
                    name_to_id(f"{service_name}Endpoint"),
                    PrivateDnsEnabled="true",
                    SecurityGroupIds=[Ref(self.security_group)],
                    ServiceName=f"com.amazonaws.{self.region}.{service_name}",
                    SubnetIds=[Ref(self.subnet)],
                    VpcEndpointType="Interface",
                    VpcId=Ref(self.vpc),
                    **opt_params,
                )
            )
        return endpoints

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Construct and return VPCEndpointsSubnet resources."""
        result = [self.subnet, self.security_group, self.default_egress_rule]

        for sg in self.authorized_sgs:
            result.extend([self.https_egress_rule(sg), self.https_ingress_rule(sg)])

        result.extend(self.interface_vpc_endpoints)

        return result


class Subnet(Construct):
    """Subnet Construct.

    Provide a subnet and associated route table. Add optional internet gateway
    and NAT gateway if needed to make this subnet public or add an optional route
    to a NAT gateway for a private subnet.
    """

    def __init__(
        self,
        name: str,
        vpc: ec2.VPC,
        cidr_block: str,
        is_public: bool = False,
        use_nat: bool = False,
        nat_to: Optional[ec2.NatGateway] = None,
    ):
        """Initialize Subnet construct.

        :param name: name of the Subnet
        :param cidr_block: address range of the subnet. Should be a subnet
            of the vpc address range (no check done).
        :param is_public: if True create a public subnet. This means that
            a route is created automatically to the vpc internet gateway.
        :param use_nat: f True and is_public is True, then add a NAT
            gateway that can be reused by private subnets.
        :param nat_to: if is_public is False and nat_to is not None,
            then create a route to the NAT gateway.
        """
        self.name = name
        self.cidr_block = cidr_block
        self.vpc = vpc
        self.is_public = is_public
        self.use_nat = use_nat
        self.nat_to = nat_to

        self._subnet: Optional[ec2.Subnet] = None
        self._route_table: Optional[ec2.RouteTable] = None
        self._nat_gateway: Optional[ec2.NatGateway] = None
        self._nat_eip: Optional[ec2.EIP] = None

    @property
    def subnet(self) -> ec2.Subnet:
        """Return a private subnet."""
        if self._subnet is None:
            self._subnet = ec2.Subnet(
                name_to_id(self.name),
                VpcId=Ref(self.vpc),
                CidrBlock=self.cidr_block,
                Tags=Tags({"Name": self.name}),
            )
        return self._subnet

    @property
    def route_table(self) -> ec2.RouteTable:
        """Return a route table for this subnet."""
        if self._route_table is None:
            self._route_table = ec2.RouteTable(
                name_to_id(f"{self.name}RouteTable"), VpcId=Ref(self.vpc)
            )
        return self._route_table

    @property
    def route_table_assoc(self) -> ec2.SubnetRouteTableAssociation:
        """Return association of route table to this subnet."""
        return ec2.SubnetRouteTableAssociation(
            name_to_id(f"{self.name}RouteTableAssoc"),
            RouteTableId=Ref(self.route_table),
            SubnetId=Ref(self.subnet),
        )

    @property
    def nat_eip(self) -> Optional[ec2.EIP]:
        """Return an elastic IP for the NAT gateway."""
        if self.use_nat and self._nat_eip is None:
            self._nat_eip = ec2.EIP(name_to_id(f"{self.name}-eip"))
        return self._nat_eip

    @property
    def nat_gateway(self) -> Optional[ec2.NatGateway]:
        """Return a NAT gateway for this subnet."""
        if self.use_nat and self._nat_gateway is None:
            self._nat_gateway = ec2.NatGateway(
                name_to_id(f"{self.name}-nat"),
                AllocationId=GetAtt(self.nat_eip, "AllocationId"),
                SubnetId=Ref(self.subnet),
            )
        return self._nat_gateway

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return resources associated with the Subnet construct."""
        result = [self.subnet, self.route_table, self.route_table_assoc]
        if self.is_public:
            result.extend(
                InternetGateway(
                    name_prefix=self.name, vpc=self.vpc, route_table=self.route_table
                ).resources(stack)
            )
            if self.use_nat:
                result.extend([self.nat_gateway, self.nat_eip])

        if self.nat_to:
            result.append(
                ec2.Route(
                    name_to_id(f"{self.name}-nat-route"),
                    RouteTableId=Ref(self.route_table),
                    DestinationCidrBlock="0.0.0.0/0",
                    NatGatewayId=Ref(self.nat_to),
                )
            )

        return result


class VPC(Construct):
    """VPC Construct.

    Provide a VPC with:
    * a private subnet which can have a NAT Gatway an optional public subnet.
    * a endpoints subnet with VPC endpoints configured according to arguments.
    * an optional s3 endpoint
    """

    def __init__(
        self,
        name: str,
        region: str,
        cidr_block: str = "10.10.0.0/16",
        private_subnet_cidr_block: str = "10.10.0.0/17",
        public_subnet_cidr_block: str = "10.10.128.0/18",
        vpc_endpoints_subnet_cidr_block: str = "10.10.192.0/18",
        internet_gateway: bool = False,
        nat_gateway: bool = False,
        s3_endpoint_policy_document: Optional[PolicyDocument] = None,
        interface_endpoints: Optional[
            list[Tuple[str, Optional[PolicyDocument]]]
        ] = None,
        tags: Optional[dict[str, str]] = None,
    ) -> None:
        """Initialize VPC Construct.

        :param name: name of the VPC
        :param region: region where to deploy the VPC
        :param cidr_block: the primary IPv4 CIDR block for the VPC
        :param private_subnet_cidr_block: The IPv4 CIDR block assigned to the
            private subnet
        :param public_subnet_cidr_block: The IPv4 CIDR block assigned to the
            public subnet
        :param vpc_endpoint_cidr_block: The IPv4 CIDR block assigned to the VPC
            endpoints subnet
        :param internet_gateway: set it to True to add an InternetGateway to this VPC
        :param nat_gateway: set it to True to add a NatGateway.
        :param s3_endpoint_policy_document: policy for s3 endpoint. If none is
            given no s3 endpoint is created.
        :param interface_endpoint: list of (<service_name>, <endpoint_policy_document>)
            tuples for each interface endpoint to create in the vpc endpoints subnet.
        :param tags: tags for the VPC
        """
        self.name = name
        self.region = region
        self.cidr_block = cidr_block
        self.public_subnet_cidr_block = public_subnet_cidr_block
        self.private_subnet_cidr_block = private_subnet_cidr_block
        self.internet_gateway = internet_gateway
        self.nat_gateway = nat_gateway
        self.vpc_endpoints_subnet_cidr_block = vpc_endpoints_subnet_cidr_block
        self.s3_endpoint_policy_document = s3_endpoint_policy_document

        self.tags: dict[str, str]
        if tags is not None:
            self.tags = tags
        else:
            self.tags = {}

        self._vpc: Optional[ec2.VPC] = None
        self._private_subnet: Optional[ec2.Subnet] = None
        self._public_subnet: Optional[ec2.Subnet] = None
        self._security_group: Optional[ec2.SecurityGroup] = None
        self._main_route_table: Optional[ec2.RouteTable] = None
        self._public_route_table: Optional[ec2.RouteTable] = None

        self.vpc_endpoints_subnet = VPCEndpointsSubnet(
            name=f"{self.name}-vpc-endpoints-subnet",
            region=region,
            cidr_block=vpc_endpoints_subnet_cidr_block,
            vpc=self.vpc,
            authorized_sgs=[self.security_group],
            interface_endpoints=interface_endpoints,
        )

    @property
    def vpc(self) -> ec2.VPC:
        """Return the VPC."""
        if self._vpc is None:
            self._vpc = ec2.VPC(
                name_to_id(self.name),
                CidrBlock=self.cidr_block,
                EnableDnsHostnames="true",
                EnableDnsSupport="true",
                Tags=Tags({"Name": self.name, **self.tags}),
            )
        return self._vpc

    @property
    def main_subnet(self) -> ec2.Subnet:
        """Return the subnet where instances/task that access Internet should run.

        If there is no NAT gateway, instances/tasks should be run in the public
        subnet to have an Internet Access.
        """
        if self.nat_gateway:
            return self.private_subnet.subnet
        else:
            return self.public_subnet.subnet

    @property
    def private_subnet(self) -> Subnet:
        """Return a private subnet for the VPC."""
        if self._private_subnet is None:
            self._private_subnet = Subnet(
                name=f"{self.name}PrivateSubnet",
                vpc=self.vpc,
                cidr_block=self.private_subnet_cidr_block,
                nat_to=self.public_subnet.nat_gateway,
            )
        return self._private_subnet

    @property
    def public_subnet(self) -> Subnet:
        """Return a public subnet for the VPC."""
        if self._public_subnet is None:
            self._public_subnet = Subnet(
                name=f"{self.name}PublicSubnet",
                vpc=self.vpc,
                cidr_block=self.public_subnet_cidr_block,
                is_public=True,
                use_nat=True,
            )
        return self._public_subnet

    # Security groups and traffic control
    @property
    def security_group(self) -> ec2.SecurityGroup:
        """Return main security group."""
        if self._security_group is None:
            sg_name = f"{self.name}SecurityGroup"
            self._security_group = ec2.SecurityGroup(
                name_to_id(f"{self.name}SecurityGroup"),
                GroupDescription=f"{self.name} main security group",
                SecurityGroupEgress=[],
                SecurityGroupIngress=[],
                VpcId=Ref(self.vpc),
                Tags=Tags({"Name": sg_name}),
            )
        return self._security_group

    @property
    def endpoints_egress_rule(self) -> ec2.SecurityGroupEgress:
        """Return egress allowing traffic to VPC interface endpoints ."""
        return ec2.SecurityGroupEgress(
            name_to_id(f"{self.name}EndpointsEgress"),
            DestinationSecurityGroupId=Ref(self.vpc_endpoints_subnet.security_group),
            FromPort="443",
            ToPort="443",
            IpProtocol="tcp",
            GroupId=Ref(self.security_group),
        )

    @property
    def s3_egress_rule(self) -> ec2.SecurityGroupEgress:
        """Return security group egress rule allowing S3 traffic."""
        return ec2.SecurityGroupEgress(
            name_to_id(f"{self.name}S3Egress"),
            DestinationPrefixListId="pl-6da54004",
            FromPort="443",
            ToPort="443",
            IpProtocol="tcp",
            GroupId=Ref(self.security_group),
        )

    @property
    def s3_route_table(self) -> ec2.RouteTable:
        """Return the route table for the s3 endpoint.

        Plug it to the route_table of the subnet where instances/tasks are running
        """
        if self.nat_gateway:
            return self.private_subnet.route_table
        else:
            return self.public_subnet.route_table

    @property
    def s3_vpc_endpoint(self) -> ec2.VPCEndPoint:
        """Return S3 VPC Endpoint.

        Note that is endpoint is also needed when using ECR as ECR stores
        images on S3.
        """
        assert self.s3_endpoint_policy_document is not None
        return ec2.VPCEndpoint(
            name_to_id(f"{self.name}S3Endpoint"),
            PolicyDocument=self.s3_endpoint_policy_document.as_dict,
            RouteTableIds=[Ref(self.s3_route_table)],
            ServiceName=f"com.amazonaws.{self.region}.s3",
            VpcEndpointType="Gateway",
            VpcId=Ref(self.vpc),
        )

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Build and return VPC resources."""
        result = []
        result.extend([self.vpc, self.security_group, self.endpoints_egress_rule])
        result.extend(self.private_subnet.resources(stack))
        result.extend(self.public_subnet.resources(stack))

        if self.s3_endpoint_policy_document:
            result.extend([self.s3_vpc_endpoint, self.s3_egress_rule])

        result.extend(self.vpc_endpoints_subnet.resources(stack))

        return result
