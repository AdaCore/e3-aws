from __future__ import absolute_import, division, print_function

from botocore.stub import ANY
from e3.aws import AWSEnv, default_region
from e3.aws.cfn import Stack
from e3.aws.cfn.ec2 import (VPC, Instance, InternetGateway, Route,
                            RouteTable, Subnet, SubnetRouteTableAssociation,
                            VPCGatewayAttachment)
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
