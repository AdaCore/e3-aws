"""Provide ecr construct tests."""
from troposphere import ecs

from e3.aws.troposphere import Stack
from e3.aws.troposphere.ecs.cluster import FargateCluster
from e3.aws.troposphere.ecs.task_definition import FargateTaskDefinition
from e3.aws.troposphere.ecs.vpc import EcsVPC


EXPECTED_FARGATE_CLUSTER = {
    "TestCluster": {
        "Properties": {
            "ClusterName": "test-cluster",
            "ClusterSettings": [{"Name": "containerInsights", "Value": "enabled"}],
            "CapacityProviders": ["FARGATE"],
            "DefaultCapacityProviderStrategy": [
                {"CapacityProvider": "FARGATE", "Weight": "1"}
            ],
            "Tags": [{"Key": "Name", "Value": "test-cluster"}],
        },
        "Type": "AWS::ECS::Cluster",
    },
    "ECSPassExecutionRolePolicy": {
        "Properties": {
            "Description": "Needed to be attached to ECSEventsRole if scheduldedtask "
            "requires ECSTaskExecutionRole",
            "ManagedPolicyName": "ECSPassExecutionRolePolicy",
            "Path": "/",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole"],
                        "Resource": {"Fn::GetAtt": ["ECSTaskExecutionRole", "Arn"]},
                    }
                ],
            },
        },
        "Type": "AWS::IAM::ManagedPolicy",
    },
    "ECSTaskExecutionRole": {
        "Properties": {
            "RoleName": "ECSTaskExecutionRole",
            "Description": "grants the Amazon ECS container agent permission to make"
            " AWS API calls on your behalf.",
            "ManagedPolicyArns": [
                "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
            ],
            "Path": "/",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": ["ecs-tasks.amazonaws.com"]},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "Tags": [{"Key": "Name", "Value": "ECSTaskExecutionRole"}],
        },
        "Type": "AWS::IAM::Role",
    },
    "ECSEventsRole": {
        "Properties": {
            "RoleName": "ECSEventsRole",
            "Description": "Allow CloudWatch Events service to run Amazon ECS tasks",
            "ManagedPolicyArns": [
                "arn:aws:iam::aws:policy/service-role/"
                "AmazonEC2ContainerServiceEventsRole",
                {"Ref": "ECSPassExecutionRolePolicy"},
            ],
            "Path": "/",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": ["events.amazonaws.com"]},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "Tags": [{"Key": "Name", "Value": "ECSEventsRole"}],
        },
        "Type": "AWS::IAM::Role",
    },
}


EXPECTED_ECS_VPC = {
    "TestVpc": {
        "Properties": {
            "CidrBlock": "10.0.0.0/16",
            "EnableDnsHostnames": True,
            "EnableDnsSupport": True,
            "Tags": [{"Key": "Name", "Value": "test-vpc"}],
        },
        "Type": "AWS::EC2::VPC",
    },
    "TestVpcSubnet": {
        "Properties": {"VpcId": {"Ref": "TestVpc"}, "CidrBlock": "10.0.0.0/24"},
        "Type": "AWS::EC2::Subnet",
    },
    "TestVpcSecurityGroup": {
        "Properties": {
            "GroupDescription": "Security group for ECS tasks",
            "SecurityGroupEgress": [],
            "SecurityGroupIngress": [],
            "VpcId": {"Ref": "TestVpc"},
        },
        "Type": "AWS::EC2::SecurityGroup",
    },
    "TestVpcIngress": {
        "Properties": {
            "CidrIp": "10.0.0.0/16",
            "FromPort": "443",
            "ToPort": "443",
            "IpProtocol": "tcp",
            "GroupId": {"Ref": "TestVpcSecurityGroup"},
        },
        "Type": "AWS::EC2::SecurityGroupIngress",
    },
    "TestVpcEgress": {
        "Properties": {
            "CidrIp": "10.0.0.0/16",
            "IpProtocol": "-1",
            "GroupId": {"Ref": "TestVpcSecurityGroup"},
        },
        "Type": "AWS::EC2::SecurityGroupEgress",
    },
    "TestVpcS3Egress": {
        "Properties": {
            "DestinationPrefixListId": "pl-6da54004",
            "FromPort": "443",
            "ToPort": "443",
            "IpProtocol": "tcp",
            "GroupId": {"Ref": "TestVpcSecurityGroup"},
        },
        "Type": "AWS::EC2::SecurityGroupEgress",
    },
    "TestVpcS3RouteTable": {
        "Properties": {"VpcId": {"Ref": "TestVpc"}},
        "Type": "AWS::EC2::RouteTable",
    },
    "TestVpcS3RouteTableAssoc": {
        "Properties": {
            "RouteTableId": {"Ref": "TestVpcS3RouteTable"},
            "SubnetId": {"Ref": "TestVpcSubnet"},
        },
        "Type": "AWS::EC2::SubnetRouteTableAssociation",
    },
    "TestVpcS3Endpoint": {
        "Properties": {
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "*",
                    }
                ],
            },
            "RouteTableIds": [{"Ref": "TestVpcS3RouteTable"}],
            "ServiceName": "com.amazonaws.eu-west-1.s3",
            "VpcEndpointType": "Gateway",
            "VpcId": {"Ref": "TestVpc"},
        },
        "Type": "AWS::EC2::VPCEndpoint",
    },
    "TestVpcCloudwatchLogsEndpoint": {
        "Properties": {
            "PrivateDnsEnabled": True,
            "SecurityGroupIds": [{"Ref": "TestVpcSecurityGroup"}],
            "ServiceName": "com.amazonaws.eu-west-1.logs",
            "SubnetIds": [{"Ref": "TestVpcSubnet"}],
            "VpcEndpointType": "Interface",
            "VpcId": {"Ref": "TestVpc"},
        },
        "Type": "AWS::EC2::VPCEndpoint",
    },
    "TestVpcSTSEndpoint": {
        "Properties": {
            "PrivateDnsEnabled": True,
            "SecurityGroupIds": [{"Ref": "TestVpcSecurityGroup"}],
            "ServiceName": "com.amazonaws.eu-west-1.sts",
            "SubnetIds": [{"Ref": "TestVpcSubnet"}],
            "VpcEndpointType": "Interface",
            "VpcId": {"Ref": "TestVpc"},
        },
        "Type": "AWS::EC2::VPCEndpoint",
    },
    "TestVpcEcrDkrEndpoint": {
        "Properties": {
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": [
                            "ecr:BatchGetImage",
                            "ecr:GetAuthorizationToken",
                            "ecr:GetDownloadUrlForLayer",
                        ],
                        "Resource": "*",
                    }
                ],
            },
            "PrivateDnsEnabled": True,
            "SecurityGroupIds": [{"Ref": "TestVpcSecurityGroup"}],
            "ServiceName": "com.amazonaws.eu-west-1.ecr.dkr",
            "SubnetIds": [{"Ref": "TestVpcSubnet"}],
            "VpcEndpointType": "Interface",
            "VpcId": {"Ref": "TestVpc"},
        },
        "Type": "AWS::EC2::VPCEndpoint",
    },
    "TestVpcEcrApiEndpoint": {
        "Properties": {
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": [
                            "ecr:BatchGetImage",
                            "ecr:GetAuthorizationToken",
                            "ecr:GetDownloadUrlForLayer",
                        ],
                        "Resource": "*",
                    }
                ],
            },
            "PrivateDnsEnabled": True,
            "SecurityGroupIds": [{"Ref": "TestVpcSecurityGroup"}],
            "ServiceName": "com.amazonaws.eu-west-1.ecr.api",
            "SubnetIds": [{"Ref": "TestVpcSubnet"}],
            "VpcEndpointType": "Interface",
            "VpcId": {"Ref": "TestVpc"},
        },
        "Type": "AWS::EC2::VPCEndpoint",
    },
}


EXPECTED_FARGATE_TASK_DEFINITION = {
    "TestFargateTaskDefinition": {
        "Properties": {
            "ContainerDefinitions": [
                {
                    "Image": "image-uri",
                    "Name": "container-def-name",
                    "LogConfiguration": {
                        "LogDriver": "awslogs",
                        "Options": {
                            "awslogs-group": "test-log-group",
                            "awslogs-create-group": True,
                            "awslogs-region": "eu-west-1",
                            "awslogs-stream-prefix": "test-prefix",
                        },
                    },
                }
            ],
            "Cpu": "1024",
            "Memory": "4096",
            "NetworkMode": "awsvpc",
            "RequiresCompatibilities": ["FARGATE"],
            "ExecutionRoleArn": {"Ref": "ECSTaskExecutionRole"},
            "TaskRoleArn": "task-role-name",
            "Tags": [{"Key": "Name", "Value": "test-fargate-task-definition"}],
        },
        "Type": "AWS::ECS::TaskDefinition",
    }
}


def test_fargate_cluster(stack: Stack) -> None:
    """Test Fargate cluster creation."""
    stack.add(FargateCluster(name="test-cluster"))
    assert stack.export()["Resources"] == EXPECTED_FARGATE_CLUSTER


def test_ecs_vpc(stack: Stack) -> None:
    """Test ECS VPC creation."""
    stack.add(EcsVPC(name="test-vpc", region="eu-west-1"))
    assert stack.export()["Resources"] == EXPECTED_ECS_VPC


def test_fargate_task_definition(stack: Stack) -> None:
    """Test fargate task definition creation."""
    docker_container_def = ecs.ContainerDefinition(
        Image="image-uri",
        Name="container-def-name",
        LogConfiguration=ecs.LogConfiguration(
            LogDriver="awslogs",
            Options={
                "awslogs-group": "test-log-group",
                "awslogs-create-group": True,
                "awslogs-region": "eu-west-1",
                "awslogs-stream-prefix": "test-prefix",
            },
        ),
    )

    stack.add(
        FargateTaskDefinition(
            name="test-fargate-task-definition",
            container_definitions=[docker_container_def],
            task_role_arn="task-role-name",
            cpu="1024",
            memory="4096",
        )
    )
    assert stack.export()["Resources"] == EXPECTED_FARGATE_TASK_DEFINITION
