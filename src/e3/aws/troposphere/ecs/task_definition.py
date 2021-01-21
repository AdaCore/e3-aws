from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Dict, List, Optional

from troposphere import AWSObject, ecs, Ref, Tags

from e3.aws import name_to_id
from e3.aws.troposphere import Construct


@dataclass(frozen=True)
class FargateTaskDefinition(Construct):
    """Define a Fargate Task.

    :param name: name of the task definition
    :param container_definition: a list of troposphere container definitions
        that make up your task
    :param cpu: number of cpu units used by the task
    :param memory: amount (in MiB) of memory used by the task
    :param family: name of a family that this task definition is registered to
    :param tags: the metadata that you apply to the task definition to help you
        categorize and organize them
    :param task_role_arn: the short name or full Amazon Resource Name (ARN) of
        the AWS Identity and Access Management (IAM) role that grants containers
        in the task permission to call AWS APIs on your behalf.
    :param volumes: the list of volume definitions for the task
    """

    name: str
    container_definitions: List[ecs.ContainerDefintion]

    cpu: str = "256"
    memory: str = "512"

    family: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=lambda: {})
    task_role_arn: Optional[str] = None
    volumes: Optional[List[ecs.Volume]] = None

    @property
    def resources(self) -> List[AWSObject]:
        """Construct and return Fargate TaskDefinition resources."""
        kwargs = {
            key: val
            for key, val in {
                "ContainerDefinitions": self.container_definitions,
                "Cpu": self.cpu,
                "Memory": self.memory,
                "Family": self.family,
                "NetworkMode": "awsvpc",
                "RequiresCompatibilities": ["FARGATE"],
                "ExecutionRoleArn": Ref(name_to_id("ECSTaskExecutionRole")),
                "TaskRoleArn": self.task_role_arn,
                "Tags": Tags({"Name": self.name, **self.tags}),
                "Volumes": self.volumes,
            }.items()
            if val is not None
        }

        return [ecs.TaskDefinition(name_to_id(self.name), **kwargs)]
