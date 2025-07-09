from __future__ import annotations

from email.mime.multipart import MIMEMultipart
from email.contentmanager import raw_data_manager
from email.message import EmailMessage
from typing import TYPE_CHECKING
from abc import abstractmethod

from e3.aws.cfn import Resource, AWSType, GetAtt, Base64, Join, Ref, Sub
from e3.aws.cfn.iam import PolicyDocument
from e3.aws.ec2.ami import AMI

if TYPE_CHECKING:
    from typing import Any

    from e3.aws.cfn.iam import InstanceProfile
    from e3.aws.cfn.ec2.security import SecurityGroup

CFN_INIT_STARTUP_SCRIPT = """#!/bin/sh
sed -i 's/scripts-user$/[scripts-user, always]/' /etc/cloud/cloud.cfg
sed -i 's/scripts_user$/[scripts_user, always]/' /etc/cloud/cloud.cfg
${Cfninit} -v --stack ${AWS::StackName} \\
                --region ${AWS::Region} \\
                --resource ${Resource} \\
                --configsets ${Config} ${CfninitOptions}\n\n"""


CFN_INIT_STARTUP_SCRIPT_WIN = (
    "C:\\ProgramData\\Amazon\\EC2-Windows\\"
    + "Launch\\Scripts\\InitializeInstance.ps1 -schedule \n"
    + "${Cfninit} -v --stack ${AWS::StackName} --region "
    + "${AWS::Region} --resource ${Resource} --configsets ${Config} "
    + "${CfninitOptions}\n\n"
)


class BlockDevice:
    """Block device for EC2 instances."""

    @property
    @abstractmethod
    def properties(self) -> dict[str, Any]: ...


class EphemeralDisk(BlockDevice):
    """Ephemeral disk."""

    def __init__(self, device_name: str, id: int = 0) -> None:
        """Initialize an ephemeral disk.

        :param device_name: name of the device associated with that disk
        :param id: id of the ephemeral disk (default is 0)
        """
        self.device_name = device_name
        self.id = id

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        return {"DeviceName": self.device_name, "VirtualName": "ephemeral%s" % self.id}


class EBSDisk(BlockDevice):
    """EBS Disk."""

    def __init__(
        self, device_name: str, size: int | None = None, encrypted: bool | None = None
    ) -> None:
        """Initialize an EBS disk.

        :param device_name: name of the device associated with that disk
        :param size: disk size in Go (default: 20Go). None can be used to
            use the same size as the original AMI
        :param encrypted: if True encrypt the device, if None take the default
            (useful when device is created from a snapshot).
        """
        self.device_name = device_name
        self.size = size
        self.encrypted = encrypted

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {
            "DeviceName": self.device_name,
            "Ebs": {"VolumeType": "gp2", "DeleteOnTermination": True},
        }
        if self.size is not None:
            result["Ebs"]["VolumeSize"] = str(self.size)

        if self.encrypted is not None:
            result["Ebs"]["Encrypted"] = self.encrypted
        return result


class EC2NetworkInterface:
    """EC2 Instance network interface."""

    def __init__(
        self,
        subnet: Subnet | None = None,
        public_ip: bool = False,
        groups: list[SecurityGroup] | None = None,
        device_index: int | None = None,
        description: str | None = None,
        interface: NetworkInterface | None = None,
    ) -> None:
        """Initialize a EC2NetworkInterface.

        :param subnet: subnet to which the interface is attached
        :param public_ip: if True assign automatically public IP address.
            Default is False.
        :param groups: list of security groups associated with the interface.
            If no group is specified, AWS will assign a default group.
        :param device_index: natural giving the interface position. 0 is the
            default interface. If set to None, some method such as
            e3.aws.cfn.ec2.Instance.add will assign automatically a device
            index
        :param description: optional description
        :param interface: an external network interface. If specified subnet,
            public_ip and groups should be set to None
        """
        if subnet is not None:
            assert (
                interface is None
            ), "cannot specify a network interface if subnet is set"
            self.subnet: Subnet | None = subnet
            self.public_ip: bool | None = public_ip
            self.groups: list[SecurityGroup] | None = groups
            self.interface_id = None
        else:
            assert not public_ip, "cannot associate automatically a public IP"
            assert groups is None, "groups should be set in the network interface"
            self.interface = interface
            self.subnet = None
            self.public_ip = False
            self.groups = None

        self.device_index = device_index
        self.description = description

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {}

        if self.subnet:
            result["AssociatePublicIpAddress"] = self.public_ip
            result["SubnetId"] = self.subnet.ref
            result["DeleteOnTermination"] = True
        else:
            assert self.interface
            result["NetworkInterfaceId"] = self.interface.ref

        if self.device_index is not None:
            result["DeviceIndex"] = self.device_index
        if self.groups:
            result["GroupSet"] = [group.ref for group in self.groups]
        if self.description is not None:
            result["Description"] = self.description
        return result


class UserData:
    """EC2 Instance user data."""

    def __init__(self) -> None:
        """Initialize user data."""
        self.parts: list[tuple[str, str, str]] = []
        self.variables: dict[str, Any] = {}

    def add(
        self,
        kind: str,
        content: str,
        name: str,
        variables: dict[str, Any] | None = None,
    ) -> None:
        """Add an entry in the user data.

        :param kind: MIME subtype (maintype is always text)
        :param content: the content associated with that value
        :param name: name of the entry (aka filename)
        """
        if variables is not None:
            self.variables.update(variables)
        self.parts.append((name, kind, content))

    @property
    def properties(self) -> Base64:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        # This is important to keep the boundary static in order to avoid
        # spurious instance reboots.
        multi_part = MIMEMultipart(
            boundary="-_- :( :( /o/ Static User Data Boundary /o/ :) :) -_-"
        )
        for name, kind, part in self.parts:
            mime_part = EmailMessage()
            raw_data_manager.set_content(mime_part, part, subtype=kind, filename=name)
            multi_part.attach(mime_part)
        return Base64(Sub(multi_part.as_string(), self.variables))


class WinUserData:
    """EC2 Windows Instance user data."""

    def __init__(self) -> None:
        """Initialize user data."""
        self.parts: list[tuple[str, str]] = []
        self.variables: dict[str, Any] = {}

    def add(
        self, kind: str, content: str, variables: dict[str, Any] | None = None
    ) -> None:
        """Add an entry in the user data.

        :param kind: script/powershell/persist
        :param content: the content associated with that value
        """
        if variables is not None:
            self.variables.update(variables)
        self.parts.append((kind, content))

    @property
    def properties(self) -> Base64:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        props = ""
        for kind, part in self.parts:
            props += "<%s>\n%s\n</%s>" % (kind, part, kind)
        return Base64(Sub(props, self.variables))


class NetworkInterface(Resource):
    """External Network Interface."""

    def __init__(
        self,
        name: str,
        subnet: Subnet,
        groups: list[SecurityGroup] | None = None,
        description: str | None = None,
    ) -> None:
        """Initialize an External Network Interface (ENI).

        :param name: logical name of the instance
        :param subnet: subnet to which the interface is attached
        :param groups: list of security groups associated with the interface.
            If no group is specified, AWS will assign a default group.
        :param description: optional description
        """
        super().__init__(name, kind=AWSType.EC2_NETWORK_INTERFACE)
        self.subnet = subnet
        self.groups = groups
        self.description = description
        self.tags: dict[str, str] = {}

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {"SubnetId": self.subnet.ref}
        if self.description is not None:
            result["Description"] = self.description
        if self.groups is not None:
            result["GroupSet"] = [group.ref for group in self.groups]
        if self.tags:
            result["Tags"] = [{"Key": k, "Value": v} for k, v in self.tags.items()]
        return result


class TemplateOrInstance(Resource):
    def __init__(self, name: str, image: AMI, kind: AWSType) -> None:
        """Initialize TemplateOrInstance.

        :param name: name of the resource (alphanumeric)
        :param image: AMI to use
        :param kind: resource kind
        """
        super().__init__(name, kind)
        self.image: AMI = image
        self.network_interfaces: dict[int, EC2NetworkInterface] = {}
        self.block_devices: list[BlockDevice] = []
        self.user_data: WinUserData | UserData | None = None
        self.instance_profile: InstanceProfile | None = None
        self.tags: dict[str, str] = {}

    def set_instance_profile(self, profile: InstanceProfile) -> None:
        self.instance_profile = profile

    def add(self, device: EC2NetworkInterface | BlockDevice) -> TemplateOrInstance:
        """Add a device to the instance.

        :param device: can be a disk or a network interface
        :return: the Instance itself
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
            raise AssertionError("invalid device %s" % device)
        return self

    def add_user_data(
        self,
        kind: str,
        content: str,
        name: str | None = None,
        variables: dict[str, Any] | None = None,
    ) -> None:
        """Add a user data entry.

        :param kind: MIME subtype (maintype is always text)
        :param content: the content associated with that value
        :param name: name of the entry (aka filename)
        """
        if self.image.is_windows:
            assert name is None
            if self.user_data is None:
                self.user_data = WinUserData()
            assert isinstance(self.user_data, WinUserData)
            self.user_data.add(kind, content, variables=variables)
        else:
            assert name is not None
            if self.user_data is None:
                self.user_data = UserData()
            assert isinstance(self.user_data, UserData)
            self.user_data.add(kind, content, name, variables=variables)

    def set_cfn_init(
        self,
        config: str = "init",
        cfn_init: str = "/usr/local/bin/cfn-init",
        resource: str | None = None,
        metadata: dict[str, Any] | None = None,
        init_script: str = "",
        use_instance_role: bool | None = False,
    ) -> None:
        """Add CFN init call on first boot of the instance.

        :param config: name of the configset to be launch (default: init)
        :param cfn_init: location of cfn-init on the instance
            (default: /usr/local/bin/cfn-init)
        :param resource: resource in which the metadata will be added. Default
            is to use current resource
        :param metadata: dict conforming to AWS::CloudFormation::Init
            specifications
        :param init_script: command to launch after cfn-init
        """
        if resource is None:
            resource = self.name

        if use_instance_role:
            assert self.instance_profile is not None
            cfn_init_options: Join | str = Join(
                [" --role ", self.instance_profile.role]
            )
        else:
            cfn_init_options = ""

        if self.image.is_windows:
            self.add_user_data(
                "powershell",
                CFN_INIT_STARTUP_SCRIPT_WIN + init_script,
                variables={
                    "Cfninit": cfn_init,
                    "Config": config,
                    "Resource": resource,
                    "CfninitOptions": cfn_init_options,
                },
            )
            self.add_user_data("persist", "true")
        else:
            self.add_user_data(
                "x-shellscript",
                CFN_INIT_STARTUP_SCRIPT + init_script,
                "init.sh",
                variables={
                    "Cfninit": cfn_init,
                    "Config": config,
                    "Resource": resource,
                    "CfninitOptions": cfn_init_options,
                },
            )

        if metadata is not None:
            self.metadata["AWS::CloudFormation::Init"] = metadata


class LaunchTemplate(TemplateOrInstance):
    """EC2 Launch template."""

    def __init__(
        self,
        name: str,
        image: AMI,
        instance_type: str = "t2.micro",
        disk_size: int | None = None,
        terminate_on_shutdown: bool = False,
        template_name: str | None = None,
        copy_ami_tags: bool = True,
    ) -> None:
        """Initialize an EC2 launch template.

        :param name: logical name of the instance
        :param image: AMI to use
        :param instance_type: kind of instance (default t2.micro)
        :param disk_size: size of disk. If None the disk size will be
            the original AMI one. Note that this affect only the root
            device of the AMI
        :param terminate_on_shutdown: if True the instance is terminated on
            shutdown
        :param template_name: if not None set the template name. If None
            logical resource id will be used for the template name
        :param copy_ami_tags: if True AMI tags will be copied into the template
            tags
        """
        super().__init__(name, image=image, kind=AWSType.EC2_LAUNCH_TEMPLATE)
        self.instance_type = instance_type
        if disk_size is not None:
            assert self.image.root_device is not None
            self.add(EBSDisk(device_name=self.image.root_device, size=disk_size))
        self.network_interfaces = {}
        self.user_data = None
        self.terminate_on_shutdown = terminate_on_shutdown
        if template_name is None:
            self.template_name = self.name
        else:
            self.template_name = template_name
        self.copy_ami_tags = copy_ami_tags

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        td: dict[str, Any] = {
            "ImageId": self.image.id,
            "InstanceType": self.instance_type,
            "BlockDeviceMappings": [bd.properties for bd in self.block_devices],
        }

        if self.instance_profile is not None:
            td["IamInstanceProfile"] = {"Name": self.instance_profile.ref}

        if self.network_interfaces:
            td["NetworkInterfaces"] = []
            for ni in self.network_interfaces.values():
                # We need to tweak a bit the result for the network
                # interface as API is not coherent between Instances and
                # Templates. Basically the key GroupSet should be replaced
                # by Groups
                prop = ni.properties
                if "GroupSet" in prop:
                    prop["Groups"] = prop["GroupSet"]
                    del prop["GroupSet"]
                td["NetworkInterfaces"].append(prop)

        if self.user_data is not None:
            td["UserData"] = self.user_data.properties

        if self.tags:
            merged_tags = {}
            if self.copy_ami_tags:
                merged_tags.update(self.image.tags)
            merged_tags.update(self.tags)

            tags = [{"Key": k, "Value": v} for k, v in merged_tags.items()]

            # Tag both volumes and instance
            td["TagSpecifications"] = [
                {"ResourceType": "instance", "Tags": tags},
                {"ResourceType": "volume", "Tags": tags},
            ]

        if self.terminate_on_shutdown:
            td["InstanceInitiatedShutdownBehavior"] = "terminate"

        return {"LaunchTemplateData": td, "LaunchTemplateName": self.template_name}


class Instance(TemplateOrInstance):
    """EC2 Instance."""

    ATTRIBUTES = (
        "AvailabilityZone",
        "PrivateDnsName",
        "PublicDnsName",
        "PrivateIp",
        "PublicIp",
    )

    def __init__(
        self,
        name: str,
        image: AMI,
        instance_type: str = "t2.micro",
        disk_size: int | None = None,
        terminate_on_shutdown: bool = False,
        copy_ami_tags: bool = False,
    ) -> None:
        """Initialize an EC2 instance.

        :param name: logical name of the instance
        :param image: AMI to use
        :param instance_type: kind of instance (default t2.micro)
        :param disk_size: size of disk. If None the disk size will be
            the original AMI one. Note that this affect only the root
            device of the AMI
        :param terminate_on_shutdown: if True the instance is terminated on
            shutdown
        :param copy_ami_tags: if True AMI tags will be copied into the template
            tags
        """
        super().__init__(name, image=image, kind=AWSType.EC2_INSTANCE)
        self.instance_type = instance_type
        if disk_size is not None:
            assert self.image.root_device is not None
            self.add(EBSDisk(device_name=self.image.root_device, size=disk_size))
        self.network_interfaces = {}
        self.user_data = None
        self.copy_ami_tags = copy_ami_tags
        self.terminate_on_shutdown = terminate_on_shutdown

    @property
    def public_ip(self) -> GetAtt:
        """Return a reference to the public Ip."""
        return GetAtt(self.name, "PublicIp")

    @property
    def private_ip(self) -> GetAtt:
        """Return a reference to the private Ip."""
        return GetAtt(self.name, "PrivateIp")

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {
            "ImageId": self.image.id,
            "InstanceType": self.instance_type,
            "BlockDeviceMappings": [bd.properties for bd in self.block_devices],
        }

        if self.instance_profile is not None:
            result["IamInstanceProfile"] = self.instance_profile.ref

        if self.network_interfaces:
            result["NetworkInterfaces"] = [
                ni.properties for ni in self.network_interfaces.values()
            ]

        if self.user_data is not None:
            result["UserData"] = self.user_data.properties

        if self.tags:
            merged_tags = {}
            if self.copy_ami_tags:
                merged_tags.update(self.image.tags)
            merged_tags.update(self.tags)

            result["Tags"] = [{"Key": k, "Value": v} for k, v in merged_tags.items()]

        if self.terminate_on_shutdown:
            result["InstanceInitiatedShutdownBehavior"] = "terminate"

        return result


class VPC(Resource):
    """EC2 VPC."""

    ATTRIBUTES = (
        "CidrBlock",
        "CidrBlockAssociations",
        "DefaultNetworkAcl",
        "DefaultSecurityGroup",
        "Ipv6CidrBlocks",
    )

    def __init__(self, name: str, cidr_block: str) -> None:
        """Initialize a VPC.

        :param name: logical name in stack
        :param cidr_block: IPv4 address range
        """
        super().__init__(name, kind=AWSType.EC2_VPC)
        self.cidr_block = cidr_block

    @property
    def properties(self) -> dict[str, Any]:
        return {
            "CidrBlock": self.cidr_block,
            "EnableDnsHostnames": True,
            "EnableDnsSupport": True,
        }

    @property
    def cidrblock(self) -> GetAtt:
        return self.getatt("CidrBlock")


class VPCEndpoint(Resource):
    """VPC Endpoint to Amazon Service."""

    def __init__(
        self,
        name: str,
        service: str,
        vpc: VPC,
        route_tables: list[RouteTable],
        policy_document: PolicyDocument,
    ) -> None:
        """Initialize a VPC endpoint.

        :param name: logical name in the stack of the entity
        :param service: name of the service to connect (s3 or dynamodb)
        :param vpc: VPC in which the endpoint is attached to
        :param route_tables: a list of route table that have access to the
            endpoint.
        :param policy_document: policy document attached to the endpoint.
        """
        super().__init__(name, kind=AWSType.EC2_VPC_ENDPOINT)
        assert service in ("dynamodb", "s3"), "Invalid service: %s" % service
        self.service = service
        self.vpc = vpc
        self.route_tables = route_tables
        self.policy_document = policy_document

    @property
    def properties(self) -> dict[str, Any]:
        return {
            "VpcId": self.vpc.ref,
            "ServiceName": Join(
                ["com.amazonaws.", Ref("AWS::Region"), "." + self.service]
            ),
            "PolicyDocument": self.policy_document.properties,
            "RouteTableIds": [rt.ref for rt in self.route_tables],
        }


class VPCInterfaceEndpoint(Resource):
    def __init__(
        self,
        name: str,
        service: str,
        subnet: Subnet,
        vpc: VPC,
        policy_document: PolicyDocument | None,
        security_group: SecurityGroup,
    ):
        """Initialize a VPC interface endpoint.

        :param name: logical name in the stack of the entity
        :param service: name of the service to connect
        :param vpc: VPC in which the endpoint is attached to
        :param subnet: The subnet in which to create an endpoint network
            interface.
        :param policy_document: policy document attached to the endpoint.
        :param security_group: security group to associate with the endpoint
            network interface
        """
        super().__init__(name, kind=AWSType.EC2_VPC_ENDPOINT)
        self.service = service
        self.vpc = vpc
        self.subnet = subnet
        self.policy_document = policy_document
        self.security_group = security_group

    @property
    def properties(self) -> dict[str, Any]:
        props: dict[str, Any] = {
            "VpcId": self.subnet.vpc.ref,
            "ServiceName": Join(
                ["com.amazonaws.", Ref("AWS::Region"), "." + self.service]
            ),
            "PrivateDnsEnabled": "true",
            "VpcEndpointType": "Interface",
            "SubnetIds": [self.subnet.ref],
            "SecurityGroupIds": [self.security_group.group_id],
        }

        if self.policy_document is not None:
            props["PolicyDocument"] = self.policy_document.properties

        return props


class Subnet(Resource):
    """EC2 subnet."""

    def __init__(self, name: str, vpc: VPC, cidr_block: str) -> None:
        """Initialize a subnet.

        :param name: logical name in stack
        :param vpc: vpc in which the subnet should be created
        :param cidr_block: IPv4 address range
        """
        super().__init__(name, kind=AWSType.EC2_SUBNET)
        self.cidr_block = cidr_block
        self.vpc = vpc

    @property
    def properties(self) -> dict[str, Any]:
        return {"CidrBlock": self.cidr_block, "VpcId": self.vpc.ref}


class InternetGateway(Resource):
    """EC2 Internet gateway."""

    def __init__(self, name: str) -> None:
        """Initialize an internet gateway.

        :param name: logical name in stack
        """
        super().__init__(name, kind=AWSType.EC2_INTERNET_GATEWAY)


class EIP(Resource):
    """EC2 Elastic IP."""

    ATTRIBUTES = ("AllocationId",)

    def __init__(
        self,
        name: str,
        gateway_attach: VPCGatewayAttachment,
        instance: Instance | None = None,
    ) -> None:
        """Initialize Elastic IP address.

        :param name: logical name in stack
        :param gateway_attach: gateway attachment
        :param instance: instance to which EIP is asstached
        """
        super().__init__(name, kind=AWSType.EC2_EIP)
        self.depends = gateway_attach.name
        self.instance = instance

    @property
    def allocation_id(self) -> GetAtt:
        return GetAtt(self.name, "AllocationId")

    @property
    def properties(self) -> dict[str, Any]:
        result: dict[str, Any] = {"Domain": "vpc"}
        if self.instance is not None:
            result["InstanceId"] = self.instance.ref
        return result


class NatGateway(Resource):
    """EC2 NatGateway."""

    def __init__(self, name: str, eip: EIP, subnet: Subnet) -> None:
        """Initialize a NAT gateway.

        :param name: logical name in stack
        :param eip: Elastic IP of the gateway
        :param subnet: subnet in which the Gateway is declared. Note that this
            should be a public subnet
        """
        super().__init__(name, kind=AWSType.EC2_NAT_GATEWAY)
        self.eip = eip
        self.subnet = subnet

    @property
    def properties(self) -> dict[str, Any]:
        return {"AllocationId": self.eip.allocation_id, "SubnetId": self.subnet.ref}


class VPCGatewayAttachment(Resource):
    """EC2 VPCGatewayAttachment."""

    def __init__(self, name: str, vpc: VPC, gateway: InternetGateway) -> None:
        """Initialize an attachment between a gateway and a VPC.

        :param name: logical name in stack
        :param vpc: vpc in which the subnet should be created
        :param gateway: a gateway
        """
        super().__init__(name, kind=AWSType.EC2_VPC_GATEWAY_ATTACHMENT)
        self.vpc = vpc
        self.gateway = gateway

    @property
    def properties(self) -> dict[str, Any]:
        return {"VpcId": self.vpc.ref, "InternetGatewayId": self.gateway.ref}


class RouteTable(Resource):
    """EC2 Route Table."""

    def __init__(self, name: str, vpc: VPC, tags: dict[str, str] | None = None) -> None:
        """Initialize a route table.

        :param name: logical name in stack
        :param vpc: a VPC instance to attach the route table to.
        :param tags: a dict of key/value tags
        """
        super().__init__(name, kind=AWSType.EC2_ROUTE_TABLE)
        self.vpc = vpc
        self.tags = tags

    @property
    def properties(self) -> dict[str, Any]:
        result: dict[str, Any] = {"VpcId": self.vpc.ref}
        if self.tags is not None:
            result["Tags"] = self.tags
        return result


class Route(Resource):
    """EC2 Route."""

    def __init__(
        self,
        name: str,
        route_table: RouteTable,
        dest_cidr_block: str,
        gateway: InternetGateway | NatGateway,
        gateway_attach: VPCGatewayAttachment,
    ) -> None:
        """Initialize a route.

        :param name: logical name in stack
        :param route_rable: a route table
        :param dest_cidr_block: route ipv4 address range
        :param gateway: the gateway
        :param gateway_attach: a gateway attachment instance
        """
        super().__init__(name, kind=AWSType.EC2_ROUTE)
        self.route_table = route_table
        self.dest_cidr_block = dest_cidr_block
        self.gateway = gateway
        self.gateway_attach = gateway_attach
        self.depends = self.gateway_attach.name

    @property
    def properties(self) -> dict[str, Any]:
        result = {
            "RouteTableId": self.route_table.ref,
            "DestinationCidrBlock": self.dest_cidr_block,
        }
        if isinstance(self.gateway, InternetGateway):
            result["GatewayId"] = self.gateway.ref
        else:
            result["NatGatewayId"] = self.gateway.ref
        return result


class SubnetRouteTableAssociation(Resource):
    """EC2 SubnetRouteTableAssociation."""

    def __init__(self, name: str, subnet: Subnet, route_table: RouteTable) -> None:
        """Initialize an association between a route table and a subnet.

        :param name: logical name in stack
        :param subnet: a subnet instance to attach the route table to.
        :param route_rable: a route table
        """
        super().__init__(name, kind=AWSType.EC2_SUBNET_ROUTE_TABLE_ASSOCIATION)
        self.subnet = subnet
        self.route_table = route_table

    @property
    def properties(self) -> dict[str, Any]:
        return {"SubnetId": self.subnet.ref, "RouteTableId": self.route_table.ref}
