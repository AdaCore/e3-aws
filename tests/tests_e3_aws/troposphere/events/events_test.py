"""Provide events construct tests."""

from e3.aws.troposphere import Stack
from e3.aws.troposphere.ecs.cluster import FargateCluster
from e3.aws.troposphere.ecs.vpc import EcsVPC
from e3.aws.troposphere.events.rule import FargateScheduledTaskRule

EXPECTED_FARGATE_SCHEDULED_RULE = {
    "TestRule": {
        "Properties": {
            "Description": "This is a test rule",
            "Name": "test-rule",
            "ScheduleExpression": "cron(0/15 * * * ? *)",
            "State": "DISABLED",
            "Targets": [
                {
                    "Arn": {"Fn::GetAtt": ["TestCluster", "Arn"]},
                    "RoleArn": {"Fn::GetAtt": ["ECSEventsRole", "Arn"]},
                    "EcsParameters": {
                        "LaunchType": "FARGATE",
                        "NetworkConfiguration": {
                            "AwsVpcConfiguration": {
                                "AssignPublicIp": "DISABLED",
                                "SecurityGroups": [{"Ref": "TestVpcSecurityGroup"}],
                                "Subnets": [{"Ref": "TestVpcSubnet"}],
                            }
                        },
                        "TaskDefinitionArn": {"Ref": "TestTask"},
                        "PlatformVersion": "1.4.0",
                    },
                    "Id": "TestTaskTarget",
                }
            ],
        },
        "Type": "AWS::Events::Rule",
    }
}


def test_fargate_scheduled_rule(stack: Stack) -> None:
    """Test fargate scheduled rule creation."""
    stack.add(
        FargateScheduledTaskRule(
            description="This is a test rule",
            ecs_cluster=FargateCluster(name="test-cluster"),
            name="test-rule",
            schedule_expression="cron(0/15 * * * ? *)",
            task_names=["test-task"],
            vpc=EcsVPC(name="test-vpc", region="eu-west-1"),
            state="DISABLED",
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_FARGATE_SCHEDULED_RULE
