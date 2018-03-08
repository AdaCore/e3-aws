from __future__ import absolute_import, division, print_function

import pytest
import yaml
from botocore.stub import ANY
from e3.aws import AWSEnv, default_region
from e3.aws.cfn import Stack
from e3.aws.cfn.ec2 import (VPC, EphemeralDisk, Instance, InternetGateway,
                            NetworkInterface, Route, RouteTable, Subnet,
                            SubnetRouteTableAssociation, UserData,
                            VPCGatewayAttachment)
from e3.aws.cfn.ec2.security import SecurityGroup
from e3.aws.ec2.ami import AMI


def test_create_network():
    s = Stack(name='teststack')

    s = Stack(name='MyStack')
    s += VPC('BuildVPC', '10.10.0.0/16')
    s += InternetGateway('Gate')
    s += Subnet('BuildPublicSubnet', s['BuildVPC'], '10.10.10.0/24')
    s += Subnet('BuildPrivateSubnet', s['BuildVPC'], '10.10.20.0/24')
    s += VPCGatewayAttachment('GateAttach',
                              s['BuildVPC'],
                              s['Gate'])
    s += RouteTable('RT', s['BuildVPC'])
    s += Route('PRoute', s['RT'],
               '0.0.0.0/0',
               s['Gate'],
               s['GateAttach'])
    s += SubnetRouteTableAssociation('RTSAssoc',
                                     s['BuildPublicSubnet'],
                                     s['RT'])
    assert s.body


def test_create_instance():
    aws_env = AWSEnv(regions=['us-east-1'], stub=True)
    with default_region('us-east-1'):
        stub = aws_env.stub('ec2', region='us-east-1')
        stub.add_response(
            'describe_images',
            {'Images': [{'ImageId': 'ami-1234',
                         'RootDeviceName': '/dev/sda1'}]},
            {'ImageIds': ANY})

        i = Instance('testmachine', AMI('ami-1234'), disk_size=20)
        assert i.properties

        i.add(EphemeralDisk('/dev/sdb', 0))
        assert i.properties

        vpc = VPC('VPC', '10.10.0.0/16')
        subnet = Subnet('Subnet', vpc, '10.10.10.0/24')
        subnet = Subnet('Subnet2', vpc, '10.10.20.0/24')
        security_group = SecurityGroup('mysgroup', vpc)
        i.add(NetworkInterface(subnet, description='first network interface'))
        i.add(NetworkInterface(subnet,
                               groups=[security_group],
                               description='2nd network interface'))
        i.add(NetworkInterface(subnet,
                               groups=[security_group],
                               description='3rd network interface',
                               device_index=3))
        assert i.properties

        with pytest.raises(AssertionError):
            i.add("non valid ec2 device")


def test_user_data_creation():
    """Test creation of user data."""
    a = UserData()
    a.add('toto.txt', 'x-shellscript', 'Hello')
    a.add('url1', 'x-include-url', 'toto.jpg')
    assert yaml.dump(a.properties)

    aws_env = AWSEnv(regions=['us-east-1'], stub=True)
    with default_region('us-east-1'):
        stub = aws_env.stub('ec2', region='us-east-1')
        stub.add_response(
            'describe_images',
            {'Images': [{'ImageId': 'ami-1234',
                         'RootDeviceName': '/dev/sda1'}]},
            {'ImageIds': ANY})

        i = Instance('testmachine', AMI('ami-1234'))
        i.add_user_data('url1', 'x-include-url', 'http://dummy')
        assert i.properties
