from __future__ import annotations
from typing import TYPE_CHECKING
from itertools import chain

from e3.aws.cfn import Stack, Join, Resource
from e3.aws.cfn.arch.security import amazon_security_groups, github_security_groups
from e3.aws.cfn.ec2 import (
    EC2NetworkInterface,
    EIP,
    Instance,
    InternetGateway,
    LaunchTemplate,
    NatGateway,
    NetworkInterface,
    Route,
    RouteTable,
    Subnet,
    SubnetRouteTableAssociation,
    VPC,
    VPCEndpoint,
    VPCInterfaceEndpoint,
    VPCGatewayAttachment,
)
from e3.aws.cfn.ec2.security import (
    Ipv4EgressRule,
    Ipv4IngressRule,
    PrefixListEgressRule,
    SecurityGroup,
)
from e3.aws.cfn.iam import PolicyDocument, Principal, PrincipalKind, InstanceRole, Allow
from e3.aws.cfn.s3 import Bucket

if TYPE_CHECKING:
    from e3.aws.cfn.iam import Policy
    from e3.aws.ec2.ami import AMI


# Prefix lists are static name used to select a list of IPs for a given
# AWS services. Currently Amazon only offer prefix lists for s3 and
# and dynamodb
PREFIX_LISTS = {
    "eu-west-1": {"s3": "pl-6da54004", "dynamodb": "pl-6fa54006"},
    "us-east-1": {"s3": "pl-63a5400a", "dynamodb": "pl-02cd2c6b"},
}


class AWSFortressError(Exception):
    """Error raised when Fortress configuration fails."""

    pass


class SubnetStack(Stack):
    """Create a subnet with a route table."""

    def __init__(
        self, name: str, vpc: VPC, cidr_block: str, description: str | None = None
    ) -> None:
        """Initialize a subnet.

        This block create a basic subnet with an empty route table

        :param name: logical name of the subnet in the stack
        :param vpc: VPC containing the subnet
        :param cidr_block: block of addresses associated with the subnet
        :param description: optional description
        """
        super().__init__(name, description)

        # Create the subnet
        self.add(Subnet(name, vpc, cidr_block))

        # Associate a route table
        self.add(RouteTable(name + "RouteTable", vpc))
        self.add(
            SubnetRouteTableAssociation(
                name + "RouteTableAssoc", self.subnet, self.route_table
            )
        )

    def add_bucket_access(self, bucket_list: list[Bucket] | list[str]) -> None:
        """Authorize access to a list of buckets using vpc endpoint.

        Note that this just allow an instance in the vpc to ask access
        to a given bucket through the endpoint. This does not change
        the bucket policy.

        The function creates also automatically the S3 VPC endpoint
        on the first call.

        :param bucket_list: list of bucket names
        """
        if self.name + "S3EndPoint" not in self:
            self.add(
                VPCEndpoint(
                    self.name + "S3EndPoint",
                    "s3",
                    self.subnet.vpc,
                    [self.route_table],
                    PolicyDocument(),
                )
            )
        for bucket in bucket_list:
            bucket_name = bucket.ref if isinstance(bucket, Bucket) else bucket
            self.s3_endpoint.policy_document.append(
                Allow(
                    to="s3:*",
                    on=[
                        Join(["arn:aws:s3:::", bucket_name]),
                        Join(["arn:aws:s3:::", bucket_name, "/*"]),
                    ],
                    apply_to=Principal(PrincipalKind.EVERYONE),
                )
            )

    @property
    def s3_endpoint(self) -> VPCEndpoint:
        resource = self[self.name + "S3EndPoint"]
        assert isinstance(resource, VPCEndpoint)
        return resource

    @property
    def subnet(self) -> Subnet:
        resource = self[self.name]
        assert isinstance(resource, Subnet)
        return resource

    @property
    def cidr_block(self) -> str:
        return self.subnet.cidr_block

    @property
    def route_table(self) -> RouteTable:
        resource = self[self.name + "RouteTable"]
        assert isinstance(resource, RouteTable)
        return resource


class VPCStack(Stack):
    """VPC stack.

    Handle a VPC with various networks elements such as subnets and gateways.
    """

    def __init__(
        self, name: str, cidr_block: str, description: str | None = None
    ) -> None:
        """Create a VPC stack.

        :param name: stack name
        :param cidr_block: ipv4 address range for the vpc
        :param description: optional description
        """
        super().__init__(name, description=description)
        self.add(VPC(self.name, cidr_block))
        self.add(InternetGateway(self.name + "InternetGateway"))
        self.add(VPCGatewayAttachment(self.name + "GateLink", self.vpc, self.gateway))

    @property
    def region(self) -> str:
        """Region in which the stack is allocated.

        :return: a region
        """
        resource = self[self.name]
        assert isinstance(resource, Resource)
        return resource.region

    def add_subnet(
        self,
        name: str,
        cidr_block: str,
        is_public: bool = False,
        use_nat: bool = False,
        nat_to: str | None = None,
    ) -> None:
        """Add a subnet.

        :param name: subnet logical name in the stack
        :param cidr_block: address range of the subnet. Should be a subnet
            of the vpc address range (no check done).
        :param is_public: if True create a public subnet. This means that
            a route is created automatically to the vpc internet gateway.
            (default: False)
        :param use_nat: if True and is_public is True, then add a NAT
            gateway that can be reused by private subnets.
            (default: False)
        :param nat_to: if is_public is False and nat_to is a string,
            then create a route to the NAT gateway of the designed
            public subnet.
        """
        # Create the subnet
        subnet_stack = SubnetStack(name, self.vpc, cidr_block)
        self.add(subnet_stack)

        if is_public:
            # Public subnet
            # Connect to the internet
            subnet_stack.add(
                Route(
                    name + "InternetRoute",
                    subnet_stack.route_table,
                    "0.0.0.0/0",
                    self.gateway,
                    self.gate_attach,
                )
            )
            if use_nat:
                # Add if needed a NAT gateway
                eip = EIP(name + "NatEIP", self.gate_attach)
                subnet_stack.add(eip)
                subnet_stack.add(
                    NatGateway(name + "NatGateway", eip, subnet_stack.subnet)
                )
        elif nat_to:
            assert nat_to in self, "invalid subnet name: %s" % nat_to
            subnet_stack_to = self[nat_to]
            assert isinstance(subnet_stack_to, SubnetStack)
            assert nat_to + "NatGateway" in subnet_stack_to, (
                "subnet %s has no NAT gateway" % nat_to
            )
            nat = subnet_stack_to[nat_to + "NatGateway"]
            assert isinstance(nat, (InternetGateway, NatGateway))
            subnet_stack.add(
                Route(
                    name + "NatRoute",
                    subnet_stack_to.route_table,
                    "0.0.0.0/0",
                    nat,
                    self.gate_attach,
                )
            )

    @property
    def vpc(self) -> VPC:
        """Get the VPC CloudFormation resource."""
        resource = self[self.name]
        assert isinstance(resource, VPC)
        return resource

    @property
    def gateway(self) -> InternetGateway:
        """Get the Gateway CloudFormation resource."""
        resource = self[self.name + "InternetGateway"]
        assert isinstance(resource, InternetGateway)
        return resource

    @property
    def gate_attach(self) -> VPCGatewayAttachment:
        """Get the GateAttachment CloudFormation resource."""
        resource = self[self.name + "GateLink"]
        assert isinstance(resource, VPCGatewayAttachment)
        return resource


class Fortress(Stack):
    def __init__(
        self,
        name: str,
        internal_server_policy: Policy,
        bastion_ami: AMI | None = None,
        allow_ssh_from: list[str] | None = None,
        description: str | None = None,
        vpc_cidr_block: str = "10.10.0.0/16",
        private_cidr_block: str = "10.10.0.0/17",
        public_cidr_block: str = "10.10.128.0/18",
        aws_endpoints_cidr_block: str = "10.10.192.0/18",
    ) -> None:
        """Create a VPC Fortress.

        This create a vpc with a public and a private subnet. Servers in the
        private subnet are only accessible through a bastion machine declared
        in the public subnet. An additional subnet is created to host AWS
        services endpoints network interfaces.

        :param name: stack name
        :param internal_server_policy: policy associated with instance role
            of private servers
        :param bastion_ami: AMI used for the bastion server. If None no bastion
            is setup
        :param allow_ssh_from: ip ranges from which ssh can be done to the
            bastion. if bastion_ami is None, parameter is discarded
        :param vpc_cidr_block: ip ranges for the associated vpc
        :param private_cidr_block: ip ranges (subset of vpc_cidr_block) used
            for private subnet
        :param public_cidr_block: ip ranges (subset of vpc_cidr_block) used
            for public subnet
        :param aws_endpoints_cidr_block: ip ranges (subset of vpc_cidr_block) used
            for aws endpoints
        """
        super().__init__(name, description)

        # Create VPC along with the three subnets
        self.add(VPCStack(self.name + "VPC", vpc_cidr_block))
        self.vpc.add_subnet(
            self.name + "PublicNet", public_cidr_block, is_public=True, use_nat=True
        )
        self.vpc.add_subnet(
            self.name + "PrivateNet", private_cidr_block, nat_to=self.name + "PublicNet"
        )
        self.vpc.add_subnet(self.name + "AWSEndpointsNet", aws_endpoints_cidr_block)

        self.amazon_groups: dict[str, SecurityGroup] = {}
        self.github_groups: dict[str, SecurityGroup] = {}

        if bastion_ami is not None:
            # Allow ssh to bastion only from a range of IP address
            bastion_sg = SecurityGroup(
                self.name + "BastionSG",
                self.vpc.vpc,
                description="security group for bastion servers",
                rules=(
                    [Ipv4IngressRule("ssh", cidr) for cidr in allow_ssh_from]
                    if allow_ssh_from is not None
                    else None
                ),
            )
            self.add(bastion_sg)

            # Create the bastion
            self.add(Instance(self.name + "Bastion", bastion_ami))
            self.bastion.tags["Name"] = "Bastion (%s)" % self.name
            self.bastion.add(
                EC2NetworkInterface(
                    self.public_subnet.subnet, public_ip=True, groups=[bastion_sg]
                )
            )

            # Create security group for internal servers
            self.add(
                SecurityGroup(
                    self.name + "InternalSG",
                    self.vpc.vpc,
                    description=(
                        "Allow ssh inside VPC and allow https "
                        "to VPC endpoints subnet"
                    ),
                    rules=[
                        Ipv4IngressRule("ssh", self.public_subnet.cidr_block),
                        Ipv4EgressRule("https", self.aws_endpoints_subnet.cidr_block),
                    ],
                )
            )
        else:
            # If no bastion is used do not authorize ssh inside the vpc
            self.add(
                SecurityGroup(
                    self.name + "InternalSG",
                    self.vpc.vpc,
                    description=(
                        "Do not allow ssh inside VPC but allow https "
                        "to the VPC endpoints subnet."
                    ),
                    rules=[
                        Ipv4EgressRule("https", self.aws_endpoints_subnet.cidr_block)
                    ],
                )
            )

        # Create security group for endpoints
        self.add(
            SecurityGroup(
                self.name + "InterfaceEndpointsSG",
                self.vpc.vpc,
                description=("Allow https from the private subnet"),
                rules=[Ipv4IngressRule("https", self.private_subnet.cidr_block)],
            )
        )

        ir = InstanceRole(self.name + "PrivServerInstanceRole")
        ir.add_policy(internal_server_policy)
        self.add(ir)

    @property
    def region(self) -> str:
        """Return the region in which the stack is allocated.

        :return: a region
        """
        return self.vpc.region

    def add_service_access(
        self,
        service_name: str,
        policy_document: PolicyDocument | None = None,
        endpoint_name: str | None = None,
    ) -> None:
        """Add an interface endpoint for a given service.

        :param service_name: name of the service for which to add an interface endpoint
        :param policy_document: optional policy to limit resources that are
            accessibles through the endpoint.
        :param endpont_name: name of the endpoint
        """
        if not endpoint_name:
            endpoint_name = f"{self.name}{service_name}EndPoint"
        if endpoint_name not in self:
            self.add(
                VPCInterfaceEndpoint(
                    name=endpoint_name,
                    service=service_name,
                    vpc=self.vpc.vpc,
                    subnet=self.aws_endpoints_subnet.subnet,
                    policy_document=policy_document,
                    security_group=self.aws_endpoints_security_group,
                )
            )

    def add_lambda_access(self, lambda_arns: list[str]) -> None:
        """Add a lambda interface endpoint with permissions to invoke given lambdas.

        :param lambda_arns: arn identifying the lambda to give access to
        """
        endpoint_name = f"{self.name}LambdaEndPoint"
        pd = PolicyDocument()
        pd.append(
            Allow(
                to=["lambda:InvokeFunction"],
                on=list(
                    chain.from_iterable(
                        ((lambda_arn, lambda_arn + ":*") for lambda_arn in lambda_arns)
                    )
                ),
                apply_to=Principal(PrincipalKind.EVERYONE),
            )
        )
        self.add_service_access(
            service_name="lambda", policy_document=pd, endpoint_name=endpoint_name
        )

    def add_secret_access(self, secret_arn: str) -> None:
        """Give read access to a given secret.

        :param secret_name: arn identifying the secret to give access to
        """
        endpoint_name = f"{self.name}SecretsManagerEndPoint"
        pd = PolicyDocument()
        pd.append(
            Allow(
                to=[
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds",
                ],
                on=[secret_arn],
                apply_to=Principal(PrincipalKind.EVERYONE),
            )
        )
        self.add_service_access(
            service_name="secretsmanager",
            policy_document=pd,
            endpoint_name=endpoint_name,
        )

    def add_network_access(
        self,
        protocol: str,
        cidr_block: str = "0.0.0.0/0",
        from_port: int | None = None,
        to_port: int | None = None,
    ) -> None:
        """Authorize some outbound protocols for internal servers.

        :param protocol: protocol name
        :param cidr_block: allowed IP range (default is all)
        :param from_port: optional starting port
        :param to_port: optional ending port
        """
        self.internal_security_group.add_rule(
            Ipv4EgressRule(protocol, cidr_block, from_port=from_port, to_port=to_port)
        )

    def add_s3_endpoint_access(self) -> None:
        internal_sg = self.internal_security_group
        internal_sg.add_rule(
            PrefixListEgressRule("https", PREFIX_LISTS[internal_sg.region]["s3"])
        )

    def private_server_security_groups(
        self,
        amazon_access: bool | None = True,
        github_access: bool | None = True,
        extra_groups: list[SecurityGroup] | None = None,
    ) -> list[SecurityGroup]:
        """Return list of security groups to apply to private servers.

        :param amazon_access: if True add a security group that allow access to
            amazon services. Default is True
        :param github_access: if True add a security group that allow access to
            github services. Default is True
        :param extra_groups: additional security groups
        :return: a list of security groups
        """
        groups = [self.internal_security_group]
        if amazon_access:
            if not self.amazon_groups:
                self.amazon_groups = amazon_security_groups(
                    self.name + "AmazonServices", self.vpc.vpc
                )
                for sg in self.amazon_groups.values():
                    self.add(sg)

            for group in self.amazon_groups.values():
                groups.append(group)

        if github_access:
            if not self.github_groups:
                self.github_groups = github_security_groups(
                    name=f"{self.name}GitHub", vpc=self.vpc.vpc, protocol="ssh"
                )
                for sg in self.github_groups.values():
                    self.add(sg)

            for group in self.github_groups.values():
                groups.append(group)

        if extra_groups:
            # Register the groups if necesssary
            for group in extra_groups:
                if group.name not in self:
                    self.add(group)
            groups += extra_groups
        return groups

    def add_private_server(
        self,
        server_ami: AMI,
        names: list[str],
        instance_type: str = "t2.micro",
        disk_size: int | None = None,
        amazon_access: bool = True,
        github_access: bool = False,
        persistent_eni: bool = False,
        is_template: bool = False,
        template_name: str | None = None,
        extra_groups: list[SecurityGroup] | None = None,
    ) -> None:
        """Add servers in the private network.

        :param server_ami: AMI to use
        :param names: list of server names (names will be used as stack logical
            names)
        :param instance_type: instance type (default: t2.micro)
        :param disk_size: disk size of the instance in Go or None to reuse the
            AMI snapshot size
        :param amazon_access: if True add a security group that allow access to
            amazon services. Default is True
        :param github_access: if True add a security group that allow access to
            github services. Default is False
        :param persistent_eni: Use a separate network interface (i.e: not
            embedded inside the EC2 instance). This is useful to preserve for
            example IP address and MAC address when a server is redeployed.
        :param is_template: create a template rather than an instance
        :param extra_groups: a list of security groups to add
        """
        groups = self.private_server_security_groups(
            amazon_access=amazon_access,
            github_access=github_access,
            extra_groups=extra_groups,
        )
        nb_sg_groups = len(groups)
        if nb_sg_groups > 16:
            raise AWSFortressError(
                f"Number of security groups is {nb_sg_groups} and exceeds the maximum "
                "number of 16 security groups allowed per network interface."
            )

        for name in names:
            instance_or_template = (
                Instance(
                    name,
                    server_ami,
                    instance_type=instance_type,
                    disk_size=disk_size,
                )
                if not is_template
                else LaunchTemplate(
                    name,
                    server_ami,
                    instance_type=instance_type,
                    disk_size=disk_size,
                    template_name=template_name,
                )
            )
            self.add(instance_or_template)

            if not persistent_eni:
                instance_or_template.add(
                    EC2NetworkInterface(
                        self.private_subnet.subnet, public_ip=False, groups=groups
                    )
                )
            else:
                network_interface = NetworkInterface(
                    name + "ENI", subnet=self.private_subnet.subnet, groups=groups
                )
                self.add(network_interface)
                instance_or_template.add(
                    EC2NetworkInterface(interface=network_interface)
                )

            instance_or_template.set_instance_profile(
                self.private_server_instance_role.instance_profile
            )
            instance_or_template.tags["Name"] = "%s (%s)" % (name, self.name)

    @property
    def vpc(self) -> VPCStack:
        resource = self[self.name + "VPC"]
        assert isinstance(resource, VPCStack)
        return resource

    @property
    def private_subnet(self) -> SubnetStack:
        resource = self.vpc[self.name + "PrivateNet"]
        assert isinstance(resource, SubnetStack)
        return resource

    @property
    def aws_endpoints_subnet(self) -> SubnetStack:
        resource = self.vpc[self.name + "AWSEndpointsNet"]
        assert isinstance(resource, SubnetStack)
        return resource

    @property
    def internal_security_group(self) -> SecurityGroup:
        resource = self[self.name + "InternalSG"]
        assert isinstance(resource, SecurityGroup)
        return resource

    @property
    def aws_endpoints_security_group(self) -> SecurityGroup:
        resource = self[self.name + "InterfaceEndpointsSG"]
        assert isinstance(resource, SecurityGroup)
        return resource

    @property
    def secretsmanager_endpoint(self) -> VPCInterfaceEndpoint:
        resource = self[self.name + "SecretsManagerEndPoint"]
        assert isinstance(resource, VPCInterfaceEndpoint)
        return resource

    @property
    def lambda_endpoint(self) -> VPCInterfaceEndpoint:
        resource = self[self.name + "LambdaEndPoint"]
        assert isinstance(resource, VPCInterfaceEndpoint)
        return resource

    @property
    def public_subnet(self) -> SubnetStack:
        resource = self.vpc[self.name + "PublicNet"]
        assert isinstance(resource, SubnetStack)
        return resource

    @property
    def bastion(self) -> Instance:
        resource = self[self.name + "Bastion"]
        assert isinstance(resource, Instance)
        return resource

    @property
    def private_server_instance_role(self) -> InstanceRole:
        resource = self[self.name + "PrivServerInstanceRole"]
        assert isinstance(resource, InstanceRole)
        return resource
