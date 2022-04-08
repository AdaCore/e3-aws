"""Provide Event Rules constructs."""
from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING


from troposphere import AWSObject, events, GetAtt, Ref

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.ec2 import VPC
from e3.aws.troposphere.ecs.cluster import FargateCluster
from e3.aws.troposphere.ecs.vpc import EcsVPC

if TYPE_CHECKING:

    from e3.aws.troposphere import Stack
    from typing import Union


@dataclass(frozen=True)
class FargateScheduledTaskRule(Construct):
    """Define an EventBridge rule that schedule fargate tasks.

    :param description: rule description
    :param ecs_cluster: ECS Cluster that should run the scheduled task
    :param name: name of the rule
    :param schedule_expression: expression that defines when the rule is
        triggered. For example to trigger the rule every 15 minutes the
        following expression can be given "cron(0/15 * * * ? *)".
    :param task_names: List of tasks to schedule
    :param vpc: VPC used to run the scheduled task
    :param state: state of the rule (DISABLED | ENABLED)
    """

    description: str
    ecs_cluster: FargateCluster
    name: str
    schedule_expression: str
    task_names: list[str]
    vpc: Union[EcsVPC, VPC]
    state: str = "DISABLED"

    def ecs_parameters(self, task_name: str) -> events.EcsParameters:
        """Return ECS parameters describing the fargate task to run.

        :param task_name: name of the task
        """
        if isinstance(self.vpc, EcsVPC):
            subnet = self.vpc.subnet
        else:
            subnet = self.vpc.main_subnet

        return events.EcsParameters(
            LaunchType="FARGATE",
            NetworkConfiguration=events.NetworkConfiguration(
                AwsVpcConfiguration=events.AwsVpcConfiguration(
                    AssignPublicIp="DISABLED",
                    SecurityGroups=[Ref(self.vpc.security_group)],
                    Subnets=[Ref(subnet)],
                )
            ),
            TaskDefinitionArn=Ref(name_to_id(f"{task_name}")),
            PlatformVersion="1.4.0",
        )

    @property
    def targets(self) -> list[events.Target]:
        """Return rule's targets."""
        return [
            events.Target(
                Arn=GetAtt(name_to_id(self.ecs_cluster.name), "Arn"),
                RoleArn=GetAtt(self.ecs_cluster.ecs_events_role.name, "Arn"),
                EcsParameters=self.ecs_parameters(task_name),
                Id=name_to_id(f"{task_name}-target"),
            )
            for task_name in self.task_names
        ]

    @property
    def rule(self) -> events.Rule:
        """Return the rule scheduling the fargate task."""
        return events.Rule(
            name_to_id(self.name),
            Description=self.description,
            Name=self.name,
            ScheduleExpression=self.schedule_expression,
            State=self.state,
            Targets=self.targets,
        )

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return FargateScheduledRule resources."""
        return [self.rule]
