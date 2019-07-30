from e3.aws.cfn import Stack, Join
from e3.aws.cfn.arch.security import amazon_security_groups
from e3.aws.cfn.ec2 import (EC2NetworkInterface, EIP, Instance,
                            InternetGateway, NatGateway,
                            NetworkInterface,
                            Route, RouteTable, Subnet,
                            SubnetRouteTableAssociation, VPC, VPCEndpoint,
                            VPCGatewayAttachment)
from e3.aws.cfn.ec2.security import (Ipv4EgressRule, Ipv4IngressRule,
                                     PrefixListEgressRule, SecurityGroup)
from e3.aws.cfn.iam import (PolicyDocument, Principal, PrincipalKind,
                            InstanceRole, Allow)
from e3.aws.cfn.s3 import Bucket


# Prefix lists are static name used to select a list of IPs for a given
# AWS services. Currently Amazon only offer prefix lists for s3 and
# and dynamodb
PREFIX_LISTS = {
    'eu-west-1': {
        's3': 'pl-6da54004',
        'dynamodb': 'pl-6fa54006'},
    'us-east-1': {
        's3': 'pl-63a5400a',
        'dynamodb': 'pl-02cd2c6b'}}


class SubnetStack(Stack):
    """Create a subnet with a route table."""

    def __init__(self, name, vpc, cidr_block, description=None):
        """Initialize a subnet.

        This block create a basic subnet with an empty route table

        :param name: logical name of the subnet in the stack
        :type name: str
        :param vpc: VPC containing the subnet
        :type vpc: VPC
        :param cidr_block: block of addresses associated with the subnet
        :type cidr_block: str
        :param description: optional description
        :type description: str | None
        """
        super(SubnetStack, self).__init__(name, description)

        # Create the subnet
        self.add(Subnet(name, vpc, cidr_block))

        # Associate a route table
        self.add(RouteTable(name + 'RouteTable', vpc))
        self.add(SubnetRouteTableAssociation(name + 'RouteTableAssoc',
                                             self.subnet,
                                             self.route_table))

    def add_bucket_access(self, bucket_list):
        """Authorize access to a list of buckets using vpc endpoint.

        Note that this just allow an instance in the vpc to ask access
        to a given bucket through the endpoint. This does not change
        the bucket policy.

        The function creates also automatically the S3 VPC endpoint
        on the first call.

        :param bucket_list: list of bucket names
        :type bucket_list: list[Bucket] | list[str]
        """
        if self.name + 'S3EndPoint' not in self:
            self.add(VPCEndpoint(self.name + 'S3EndPoint',
                                 's3',
                                 self.subnet.vpc,
                                 [self.route_table],
                                 PolicyDocument()))
        for bucket in bucket_list:
            if isinstance(bucket, Bucket):
                bucket_name = bucket.ref
            else:
                bucket_name = bucket
            self.s3_endpoint.policy_document.append(
                Allow(to='s3:*',
                      on=[Join(['arn:aws:s3:::', bucket_name]),
                          Join(['arn:aws:s3:::', bucket_name, '/*'])],
                      apply_to=Principal(PrincipalKind.EVERYONE)))

    @property
    def s3_endpoint(self):
        return self[self.name + 'S3EndPoint']

    @property
    def subnet(self):
        return self[self.name]

    @property
    def cidr_block(self):
        return self[self.name].cidr_block

    @property
    def route_table(self):
        return self[self.name + 'RouteTable']


class VPCStack(Stack):
    """VPC stack.

    Handle a VPC with various networks elements such as subnets and gateways.
    """

    def __init__(self, name, cidr_block, description=None):
        """Create a VPC stack.

        :param name: stack name
        :type name: str
        :param cidr_block: ipv4 address range for the vpc
        :type cird_block: str
        :param description: optional description
        :type description: str | None
        """
        super(VPCStack, self).__init__(name, description)
        self.add(VPC(self.name, cidr_block))
        self.add(InternetGateway(self.name + 'InternetGateway'))
        self.add(VPCGatewayAttachment(self.name + 'GateLink',
                                      self.vpc, self.gateway))

    @property
    def region(self):
        """Region in which the stack is allocated.

        :return: a region
        :rtype: str
        """
        return self[self.name].region

    def add_subnet(self,
                   name,
                   cidr_block,
                   is_public=False,
                   use_nat=False,
                   nat_to=None):
        """Add a subnet.

        :param name: subnet logical name in the stack
        :type name: str
        :param cidr_block: address range of the subnet. Should be a subnet
            of the vpc address range (no check done).
        :type cidr_block: str
        :param is_public: if True create a public subnet. This means that
            a route is created automatically to the vpc internet gateway.
            (default: False)
        :type is_public: bool
        :param use_nat: if True and is_public is True, then add a NAT
            gateway that can be reused by private subnets.
            (default: False)
        :type use_nat: bool
        :param nat_to: if is_public is False and nat_to is a string,
            then create a route to the NAT gateway of the designed
            public subnet.
        :type nat_to: None | str
        """
        # Create the subnet
        self.add(SubnetStack(name, self.vpc, cidr_block))

        if is_public:
            # Public subnet
            # Connect to the internet
            self[name].add(Route(name + 'InternetRoute',
                                 self[name].route_table,
                                 "0.0.0.0/0",
                                 self.gateway,
                                 self.gate_attach))
            if use_nat:
                # Add if needed a NAT gateway
                self[name].add(EIP(name + 'NatEIP', self.gate_attach))
                self[name].add(NatGateway(name + 'NatGateway',
                                          self[name][name + 'NatEIP'],
                                          self[name].subnet))
        elif nat_to:
            assert nat_to in self, 'invalid subnet name: %s' % nat_to
            assert nat_to + 'NatGateway' in self[nat_to], \
                'subnet %s has no NAT gateway' % nat_to
            self[name].add(Route(name + 'NatRoute',
                                 self[name].route_table,
                                 "0.0.0.0/0",
                                 self[nat_to][nat_to + 'NatGateway'],
                                 self.gate_attach))

    @property
    def vpc(self):
        """Get the VPC CloudFormation resource."""
        return self[self.name]

    @property
    def gateway(self):
        """Get the Gateway CloudFormation resource."""
        return self[self.name + 'InternetGateway']

    @property
    def gate_attach(self):
        """Get the GateAttachment CloudFormation resource."""
        return self[self.name + 'GateLink']


class Fortress(Stack):
    def __init__(self,
                 name,
                 internal_server_policy,
                 bastion_ami=None,
                 allow_ssh_from=None,
                 description=None,
                 vpc_cidr_block='10.10.0.0/16',
                 private_cidr_block='10.10.0.0/17',
                 public_cidr_block='10.10.128.0/17'):
        """Create a VPC Fortress.

        This create a vpc with a public and a private subnet. Servers in the
        private subnet are only accessible through a bastion machine declare
        in the public subnet.

        :param name: stack name
        :type name: str
        :param internal_server_policy: policy associated with instance role
            of private servers
        :type internal_server_policy: Policy
        :param bastion_ami: AMI used for the bastion server. If None no bastion
            is setup
        :type bastion_ami: AMI | None
        :param allow_ssh_from: ip ranges from which ssh can be done to the
            bastion. if bastion_ami is None, parameter is discarded
        :type allow_ssh_from: str | None
        :param vpc_cidr_block: ip ranges for the associated vpc
        :type vpc_cidr_block: str
        :param private_cidr_block: ip ranges (subset of vpc_cidr_block) used
            for private subnet
        :type private_cidr_block: str
        :param public_cidr_block: ip ranges (subset of vpc_cidr_block) used
            for public subnet
        :type public_cidr_block: str
        """
        super(Fortress, self).__init__(name, description)

        # Create VPC along with the two subnets
        self.add(VPCStack(self.name + 'VPC', vpc_cidr_block))
        self.vpc.add_subnet(self.name + 'PublicNet', public_cidr_block,
                            is_public=True, use_nat=True)
        self.vpc.add_subnet(self.name + 'PrivateNet', private_cidr_block,
                            nat_to=self.name + 'PublicNet')

        self.amazon_groups = amazon_security_groups(
            self.name + 'AmazonServices',
            self.vpc.vpc)

        for sg in self.amazon_groups.values():
            self.add(sg)

        if bastion_ami is not None:
            # Allow ssh to bastion only from a range of IP address
            self.add(SecurityGroup(
                self.name + 'BastionSG',
                self.vpc.vpc,
                description='security group for bastion servers',
                rules=[Ipv4IngressRule('ssh', cidr)
                       for cidr in allow_ssh_from]))

            # Create the bastion
            self.add(Instance(self.name + 'Bastion', bastion_ami))
            self.bastion.tags['Name'] = 'Bastion (%s)' % self.name
            self.bastion.add(
                EC2NetworkInterface(self.public_subnet.subnet,
                                    public_ip=True,
                                    groups=[self[self.name + 'BastionSG']]))

            # Create security group for internal servers
            self.add(SecurityGroup(
                self.name + 'InternalSG',
                self.vpc.vpc,
                description='Allow ssh inside VPC',
                rules=[Ipv4IngressRule('ssh', self.public_subnet.cidr_block)]))
        else:
            # If no bastion is used do not authorize ssh inside the vpc
            self.add(SecurityGroup(
                self.name + 'InternalSG',
                self.vpc.vpc,
                description='Do not allow ssh inside VPC'))

        ir = InstanceRole(self.name + 'PrivServerInstanceRole')
        ir.add_policy(internal_server_policy)
        self.add(ir)

    @property
    def region(self):
        """Return the region in which the stack is allocated.

        :return: a region
        :rtype: str
        """
        return self[self.name + 'VPC'].region

    def add_network_access(self, protocol, cidr_block='0.0.0.0/0'):
        """Authorize some ooutbound protocols for internal servers.

        :param protocol: protocol name
        :type protocol: str
        :param cidr_block: allowed IP range (default is all)
        :type cird_block: str
        """
        self[self.name + 'InternalSG'].add_rule(
            Ipv4EgressRule(protocol, cidr_block))

    def add_s3_endpoint_access(self):
        self[self.name + 'InternalSG'].add_rule(
            PrefixListEgressRule(
                'https',
                PREFIX_LISTS[self[self.name + 'InternalSG'].region]['s3']))

    def add_private_server(self, server_ami, names,
                           instance_type='t2.micro',
                           disk_size=None,
                           amazon_access=True,
                           persistent_eni=False):
        """Add servers in the private network.

        :param server_ami: AMI to use
        :type server_ami: AMI
        :param names: list of server names (names will be used as stack logical
            names)
        :type names: list[str]
        :param instance_type: instance type (default: t2.micro)
        :type instance_type: str
        :param disk_size: disk size of the instance in Go or None to reuse the
            AMI snapshot size
        :type disk_size: int | None
        :param amazon_access: if True add a security group that allow access to
            amazon services. Default is True
        :type amazon_access: bool
        :param persistent_eni: Use a separate network interface (i.e: not
            embedded inside the EC2 instance). This is useful to preserve for
            example IP address and MAC address when a server is redeployed.
        :type persistent_eni: bool
        """
        groups = [self[self.name + 'InternalSG']]
        if amazon_access:
            for group in self.amazon_groups.values():
                groups.append(group)

        for name in names:
            self.add(Instance(name, server_ami,
                              instance_type=instance_type,
                              disk_size=disk_size))
            if not persistent_eni:
                self[name].add(
                    EC2NetworkInterface(self.private_subnet.subnet,
                                        public_ip=False,
                                        groups=groups))
            else:
                network_interface = NetworkInterface(
                    name + 'ENI',
                    subnet=self.private_subnet.subnet,
                    groups=groups)
                self.add(network_interface)
                self[name].add(
                    EC2NetworkInterface(interface=network_interface))

            self[name].set_instance_profile(
                self[self.name + 'PrivServerInstanceRole'].instance_profile)
            self[name].tags['Name'] = '%s (%s)' % (name, self.name)

    @property
    def vpc(self):
        return self[self.name + 'VPC']

    @property
    def private_subnet(self):
        return self.vpc[self.name + 'PrivateNet']

    @property
    def public_subnet(self):
        return self.vpc[self.name + 'PublicNet']

    @property
    def bastion(self):
        return self[self.name + 'Bastion']
