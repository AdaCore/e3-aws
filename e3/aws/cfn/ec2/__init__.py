from email.mime.multipart import MIMEMultipart
from email.contentmanager import raw_data_manager
from email.message import EmailMessage

from e3.aws.cfn import Resource, AWSType, GetAtt, Base64, Join, Ref
from e3.aws.cfn.iam import PolicyDocument
from e3.aws.ec2.ami import AMI
from e3.env import Env


CFN_INIT_STARTUP_SCRIPT = """#!/bin/sh
sed -i 's/scripts-user$/[scripts-user, always]/' /etc/cloud/cloud.cfg
%(cfn_init)s -v --stack %(stack)s \\
                --region %(region)s \\
                --resource %(resource)s \\
                --configsets %(config)s

"""


CFN_INIT_STARTUP_SCRIPT_WIN = "C:\\ProgramData\\Amazon\\EC2-Windows\\" + \
    "Launch\\Scripts\\InitializeInstance.ps1 -schedule \n" + \
    "%(cfn_init)s -v --stack %(stack)s --region " + \
    "%(region)s --resource %(resource)s --configsets %(config)s \n\n"


class BlockDevice(object):
    """Block device for EC2 instances."""

    pass


class EphemeralDisk(BlockDevice):
    """Ephemeral disk."""

    def __init__(self, device_name, id=0):
        """Initialize an ephemeral disk.

        :param device_name: name of the device associated with that disk
        :type device_name: str
        :param id: id of the ephemeral disk (default is 0)
        :type id: int
        """
        assert isinstance(id, int)
        self.device_name = device_name
        self.id = id

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        return {"DeviceName": self.device_name,
                "VirtualName": "ephemeral%s" % self.id}


class EBSDisk(BlockDevice):
    """EBS Disk."""

    def __init__(self, device_name, size=20, encrypted=None):
        """Initialize an EBS disk.

        :param device_name: name of the device associated with that disk
        :type device_name: str
        :param size: disk size in Go (default: 20Go)
        :type size: int
        :param encrypted: if True encrypt the device, if None take the default
            (useful when device is created from a snapshot).
        :type encrypted: bool | None
        """
        self.device_name = device_name
        self.size = size
        self.encrypted = encrypted

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {"DeviceName": self.device_name,
                  "Ebs": {"VolumeSize": str(self.size),
                          "VolumeType": "gp2",
                          "DeleteOnTermination": True}}
        if self.encrypted is not None:
            result['Ebs']['Encrypted'] = self.encrypted
        return result


class EC2NetworkInterface(object):
    """EC2 Instance network interface."""

    def __init__(self,
                 subnet=None,
                 public_ip=False,
                 groups=None,
                 device_index=None,
                 description=None,
                 interface=None):
        """Initialize a EC2NetworkInterface.

        :param subnet: subnet to which the interface is attached
        :type subnet: e3.aws.cfn.ec2.Subnet
        :param public_ip: if True assign automatically public IP address.
            Default is False.
        :type public_ip: bool
        :param groups: list of security groups associated with the interface.
            If no group is specified, AWS will assign a default group.
        :type groups: list[SecurityGroup] | None
        :param device_index: natural giving the interface position. 0 is the
            default interface. If set to None, some method such as
            e3.aws.cfn.ec2.Instance.add will assign automatically a device
            index
        :type device_index: 0 | None
        :param description: optional description
        :type description: str | None
        :param interface: an external network interface. If specified subnet,
            public_ip and groups should be set to None
        :type interface: NetworkInterface | None
        """
        if subnet is not None:
            assert isinstance(subnet, Subnet), \
                'unexpected type for subnet: %s' % subnet
            assert interface is None, \
                'cannot specify a network interface if subnet is set'
            self.subnet = subnet
            self.public_ip = public_ip
            self.groups = groups
            self.interface_id = None
        else:
            assert isinstance(interface, NetworkInterface), \
                'if not subnet is provided a valid network interface ' \
                'should be passed'
            assert not public_ip, 'cannot associate automatically a public IP'
            assert groups is None, \
                'groups should be set in the network interface'
            self.interface = interface
            self.subnet = None
            self.public_ip = False
            self.groups = None

        self.device_index = device_index
        self.description = description

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {}

        if self.subnet:
            result['AssociatePublicIpAddress'] = self.public_ip
            result['SubnetId'] = self.subnet.ref
            result['DeleteOnTermination'] = True
        else:
            result['NetworkInterfaceId'] = self.interface.ref

        if self.device_index is not None:
            result['DeviceIndex'] = self.device_index
        if self.groups:
            result['GroupSet'] = [group.ref for group in self.groups]
        if self.description is not None:
            result['Description'] = self.description
        return result


class UserData(object):
    """EC2 Instance user data."""

    def __init__(self):
        """Initialize user data."""
        self.parts = []

    def add(self, kind, content, name):
        """Add an entry in the user data.

        :param kind: MIME subtype (maintype is always text)
        :type kind: str
        :param content: the content associated with that value
        :type content: str
        :param name: name of the entry (aka filename)
        :type name: str
        """
        self.parts.append((name, kind, content))

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        # This is important to keep the boundary static in order to avoid
        # spurious instance reboots.
        multi_part = MIMEMultipart(
            boundary='-_- :( :( /o/ Static User Data Boundary /o/ :) :) -_-')
        for name, kind, part in self.parts:
            mime_part = EmailMessage()
            raw_data_manager.set_content(mime_part,
                                         part,
                                         subtype=kind,
                                         filename=name)
            multi_part.attach(mime_part)
        return Base64(multi_part.as_string())


class WinUserData(object):
    """EC2 Windows Instance user data."""

    def __init__(self):
        """Initialize user data."""
        self.parts = []

    def add(self, kind, content):
        """Add an entry in the user data.

        :param kind: script/powershell/persist
        :type kind: str
        :param content: the content associated with that value
        :type content: str
        """
        self.parts.append((kind, content))

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        props = []
        for kind, part in self.parts:
            props.append('<%s>\n%s\n</%s>' % (kind, part, kind))
        return Base64(Join(props))


class NetworkInterface(Resource):
    """External Network Interface."""

    def __init__(self, name, subnet, groups=None, description=None):
        """Initialize an External Network Interface (ENI).

        :param name: logical name of the instance
        :type name: str
        :param subnet: subnet to which the interface is attached
        :type subnet: e3.aws.cfn.ec2.Subnet
        :param groups: list of security groups associated with the interface.
            If no group is specified, AWS will assign a default group.
        :type groups: list[SecurityGroup] | None
        :param description: optional description
        :type description: str | None
        """
        super(NetworkInterface, self).__init__(
            name,
            kind=AWSType.EC2_NETWORK_INTERFACE)
        assert isinstance(subnet, Subnet)
        self.subnet = subnet
        self.groups = groups
        self.description = description

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {'SubnetId': self.subnet.ref}
        if self.description is not None:
            result['Description'] = self.description
        if self.groups is not None:
            result['GroupSet'] = [group.ref for group in self.groups]
        return result


class Instance(Resource):
    """EC2 Instance."""

    ATTRIBUTES = ('AvailabilityZone',
                  'PrivateDnsName',
                  'PublicDnsName',
                  'PrivateIp',
                  'PublicIp')

    def __init__(self, name, image,
                 instance_type='t2.micro',
                 disk_size=None):
        """Initialize an EC2 instance.

        :param name: logical name of the instance
        :type name: str
        :param image: AMI to use
        :type image_id: e3.aws.ec2.ami.AMI
        :param instance_type: kind of instance (default t2.micro)
        :type instance_type: str
        :param disk_size: size of disk. If None the disk size will be
            the original AMI one. Note that this affect only the root
            device of the AMI
        :type disk_size: int | None
        """
        super(Instance, self).__init__(name, kind=AWSType.EC2_INSTANCE)
        assert isinstance(image, AMI)
        self.image = image
        self.instance_type = instance_type
        self.block_devices = []
        if disk_size is not None:
            self.add(EBSDisk(device_name=self.image.root_device,
                             size=disk_size))
        self.instance_profile = None
        self.network_interfaces = {}
        self.user_data = None
        self.tags = {}

    @property
    def public_ip(self):
        """Return a reference to the public Ip.

        :rtype: e3.aws.cfn.GetAtt
        """
        return GetAtt(self.name, 'PublicIp')

    @property
    def private_ip(self):
        """Return a reference to the private Ip.

        :rtype: e3.aws.cfn.GetAtt
        """
        return GetAtt(self.name, 'PrivateIp')

    def set_instance_profile(self, profile):
        self.instance_profile = profile

    def add(self, device):
        """Add a device to the instance.

        :param device: can be a disk or a network interface
        :type device: EC2NetworkInterface | BockDevice
        :return: the Instance itself
        :rtype: Instance
        """
        if isinstance(device, EC2NetworkInterface):
            if device.device_index is None:
                # Assign automatically a device index
                index = max(list(self.network_interfaces.keys()) + [-1]) + 1
                device.device_index = index
            else:
                # Ensure the device is not already present
                assert device.device_index not in self.network_interfaces
                index = device.device_index

            self.network_interfaces[index] = device
        elif isinstance(device, BlockDevice):
            self.block_devices.append(device)
        else:
            assert False, 'invalid device %s' % device
        return self

    def set_cfn_init(self, stack,
                     config='init',
                     cfn_init='/usr/local/bin/cfn-init',
                     region=None,
                     resource=None,
                     metadata=None,
                     init_script=''):
        """Add CFN init call on first boot of the instance.

        :param stack: name of the stack containing the cfn metadata
        :type stack: str
        :param config: name of the configset to be launch (default: init)
        :type config: str
        :param cfn_init: location of cfn-init on the instance
            (default: /usr/local/bin/cfn-init)
        :type cfn_init: str
        :param region: AWS region. if not specified use current default region
        :type region: name | None
        :param resource: resource in which the metadata will be added. Default
            is to use current resource
        :type resource: str | None
        :param metadata: dict conforming to AWS::CloudFormation::Init
            specifications
        :type metadata: dict | None
        :param init_script: command to launch after cfn-init
        :type init_script: powershell command for windows and bash command for
            linuxes
        """
        if region is None:
            region = Env().aws_env.default_region
        if resource is None:
            resource = self.name
        if self.image.is_windows:
            self.add_user_data(
                'powershell',
                CFN_INIT_STARTUP_SCRIPT_WIN % {
                    'region': region,
                    'stack': stack,
                    'resource': resource,
                    'cfn_init': cfn_init,
                    'config': config} +
                init_script)
            self.add_user_data('persist', 'true')
        else:
            self.add_user_data(
                'x-shellscript',
                CFN_INIT_STARTUP_SCRIPT % {'region': region,
                                           'stack': stack,
                                           'resource': resource,
                                           'cfn_init': cfn_init,
                                           'config': config} +
                init_script,
                'init.sh')
        if metadata is not None:
            self.metadata['AWS::CloudFormation::Init'] = metadata

    def add_user_data(self, kind, content, name=None):
        """Add a user data entry.

        :param kind: MIME subtype (maintype is always text)
        :type kind: str
        :param content: the content associated with that value
        :type content: str
        :param name: name of the entry (aka filename)
        :type name: str
        """
        if self.image.is_windows:
            assert name is None
            if self.user_data is None:
                self.user_data = WinUserData()
            self.user_data.add(kind, content)
        else:
            assert name is not None
            if self.user_data is None:
                self.user_data = UserData()
            self.user_data.add(kind, content, name)

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {'ImageId': self.image.id,
                  'InstanceType': self.instance_type,
                  'BlockDeviceMappings': [bd.properties
                                          for bd in self.block_devices]}
        if self.instance_profile is not None:
            result['IamInstanceProfile'] = self.instance_profile.ref
        if self.network_interfaces:
            result['NetworkInterfaces'] = \
                [ni.properties
                 for ni in self.network_interfaces.values()]
        if self.user_data is not None:
            result['UserData'] = self.user_data.properties
        if self.tags:
            result['Tags'] = [{'Key': k, 'Value': v}
                              for k, v in self.tags.items()]
        return result


class VPC(Resource):
    """EC2 VPC."""

    ATTRIBUTES = ('CidrBlock',
                  'CidrBlockAssociations',
                  'DefaultNetworkAcl',
                  'DefaultSecurityGroup',
                  'Ipv6CidrBlocks')

    def __init__(self, name, cidr_block):
        """Initialize a VPC.

        :param name: logical name in stack
        :type name: str
        :param cidr_block: IPv4 address range
        :type cidr_block: str
        """
        super(VPC, self).__init__(name, kind=AWSType.EC2_VPC)
        self.cidr_block = cidr_block

    @property
    def properties(self):
        return {'CidrBlock': self.cidr_block,
                'EnableDnsHostnames': True,
                'EnableDnsSupport': True}

    @property
    def cidrblock(self):
        return self.getatt('CidrBlock')


class VPCEndpoint(Resource):
    """VPC Endpoint to Amazon Service."""

    def __init__(self, name, service, vpc, route_tables, policy_document):
        """Initialize a VPC endpoint.

        :param name: logical name in the stack of the entity
        :type name: str
        :param service: name of the service to connect (s3 or dynamodb)
        :type service: str
        :param vpc: VPC in which the endpoint is attached to
        :type vpc: e3.aws.cfn.ec2.VPC
        :param route_tables: a list of route table that have access to the
            endpoint.
        :type route_tables: list[RouteTable]
        :param policy_document: policy document attached to the endpoint.
        :type policy_docyment: e3.aws.cfn.ec2.security.PolicyDocument
        """
        super(VPCEndpoint, self).__init__(name, kind=AWSType.EC2_VPC_ENDPOINT)
        assert service in ('dynamodb', 's3'), 'Invalid service: %s' % service
        self.service = service
        assert isinstance(vpc, VPC), 'VPC instance expected'
        self.vpc = vpc
        self.route_tables = route_tables
        for rt in self.route_tables:
            assert isinstance(rt, RouteTable), 'RouteTable expected'
        self.policy_document = policy_document
        assert isinstance(self.policy_document, PolicyDocument)

    @property
    def properties(self):
        return {
            'VpcId': self.vpc.ref,
            'ServiceName': Join(["com.amazonaws.",
                                 Ref("AWS::Region"),
                                 "." + self.service]),
            'PolicyDocument': self.policy_document.properties,
            'RouteTableIds': [rt.ref for rt in self.route_tables]}


class Subnet(Resource):
    """EC2 subnet."""

    def __init__(self, name, vpc, cidr_block):
        """Initialize a subnet.

        :param name: logical name in stack
        :type name: str
        :param vpc: vpc in which the subnet should be created
        :type vpc: VPC
        :param cidr_block: IPv4 address range
        :type cidr_block: str
        """
        super(Subnet, self).__init__(name, kind=AWSType.EC2_SUBNET)
        self.cidr_block = cidr_block
        assert isinstance(vpc, VPC)
        self.vpc = vpc

    @property
    def properties(self):
        return {'CidrBlock': self.cidr_block,
                'VpcId': self.vpc.ref}


class InternetGateway(Resource):
    """EC2 Internet gateway."""

    def __init__(self, name):
        """Initialize an internet gateway.

        :param name: logical name in stack
        :type name: str
        """
        super(InternetGateway, self).__init__(
            name, kind=AWSType.EC2_INTERNET_GATEWAY)


class EIP(Resource):
    """EC2 Elastic IP."""

    ATTRIBUTES = ('AllocationId', )

    def __init__(self, name, gateway_attach):
        """Initialize Elastic IP address.

        :param name: logical name in stack
        :type name: str
        :param gateway_attach: gateway attachment
        :type gateway_attach: VPCGatewayAttachment
        """
        super(EIP, self).__init__(name, kind=AWSType.EC2_EIP)
        assert isinstance(gateway_attach, VPCGatewayAttachment)
        self.depends = gateway_attach.name

    @property
    def allocation_id(self):
        return GetAtt(self.name, 'AllocationId')

    @property
    def properties(self):
        return {'Domain': 'vpc'}


class NatGateway(Resource):
    """EC2 NatGateway."""

    def __init__(self, name, eip, subnet):
        """Initialize a NAT gateway.

        :param name: logical name in stack
        :type name: str
        :param eip: Elastic IP of the gateway
        :type eip: EIP
        :param subnet: subnet in which the Gateway is declared. Note that this
            should be a public subnet
        :type subnet: Subnet
        """
        super(NatGateway, self).__init__(name, kind=AWSType.EC2_NAT_GATEWAY)
        self.eip = eip
        assert isinstance(subnet, Subnet)
        self.subnet = subnet

    @property
    def properties(self):
        return {'AllocationId': self.eip.allocation_id,
                'SubnetId': self.subnet.ref}


class VPCGatewayAttachment(Resource):
    """EC2 VPCGatewayAttachment."""

    def __init__(self, name, vpc, gateway):
        """Initialize an attachment between a gateway and a VPC.

        :param name: logical name in stack
        :type name: str
        :param vpc: vpc in which the subnet should be created
        :type vpc: VPC
        :param gateway: a gateway
        :type gateway: InternetGateway
        """
        super(VPCGatewayAttachment, self).__init__(
            name, kind=AWSType.EC2_VPC_GATEWAY_ATTACHMENT)
        assert isinstance(vpc, VPC)
        assert isinstance(gateway, InternetGateway)
        self.vpc = vpc
        self.gateway = gateway

    @property
    def properties(self):
        return {'VpcId': self.vpc.ref,
                'InternetGatewayId': self.gateway.ref}


class RouteTable(Resource):
    """EC2 Route Table."""

    def __init__(self, name, vpc, tags=None):
        """Initialize a route table.

        :param name: logical name in stack
        :type name: str
        :param vpc: a VPC instance to attach the route table to.
        :type vpc: e3.aws.cfn.ec2.VPC
        :param tags: a dict of key/value tags
        :type tags: dict
        """
        super(RouteTable, self).__init__(name, kind=AWSType.EC2_ROUTE_TABLE)
        assert isinstance(vpc, VPC)
        self.vpc = vpc
        self.tags = tags

    @property
    def properties(self):
        result = {'VpcId': self.vpc.ref}
        if self.tags is not None:
            result['Tags'] = self.tags
        return result


class Route(Resource):
    """EC2 Route."""

    def __init__(self, name, route_table, dest_cidr_block,
                 gateway,
                 gateway_attach):
        """Initialize a route.

        :param name: logical name in stack
        :type name: str
        :param route_rable: a route table
        :type route_table: RouteTable
        :param dest_cidr_block: route ipv4 address range
        :type dest_cidr_block: str
        :param gateway: the gateway
        :type gateway: InternetGateway | NatGateway
        :param gateway_attach: a gateway attachment instance
        :type gateway_attach: VPCGatewayAttachment
        """
        super(Route, self).__init__(name, kind=AWSType.EC2_ROUTE)
        assert isinstance(route_table, RouteTable)
        assert isinstance(gateway, InternetGateway) or \
            isinstance(gateway, NatGateway)
        self.route_table = route_table
        self.dest_cidr_block = dest_cidr_block
        self.gateway = gateway
        self.gateway_attach = gateway_attach
        self.depends = self.gateway_attach.name

    @property
    def properties(self):
        result = {'RouteTableId': self.route_table.ref,
                  'DestinationCidrBlock': self.dest_cidr_block}
        if isinstance(self.gateway, InternetGateway):
            result['GatewayId'] = self.gateway.ref
        else:
            result['NatGatewayId'] = self.gateway.ref
        return result


class SubnetRouteTableAssociation(Resource):
    """EC2 SubnetRouteTableAssociation."""

    def __init__(self, name, subnet, route_table):
        """Initialize an association between a route table and a subnet.

        :param name: logical name in stack
        :type name: str
        :param subnet: a subnet instance to attach the route table to.
        :type subnet: e3.aws.cfn.ec2.Subnet
        :param route_rable: a route table
        :type route_table: RouteTable
        """
        super(SubnetRouteTableAssociation, self).__init__(
            name, kind=AWSType.EC2_SUBNET_ROUTE_TABLE_ASSOCIATION)
        self.subnet = subnet
        self.route_table = route_table

    @property
    def properties(self):
        return {'SubnetId': self.subnet.ref,
                'RouteTableId': self.route_table.ref}
