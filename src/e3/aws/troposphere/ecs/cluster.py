from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING


from troposphere import AWSObject, ecs, GetAtt, Ref, Tags

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere.iam.managed_policy import ManagedPolicy
from e3.aws.troposphere.iam.policy_statement import PolicyStatement, Trust

if TYPE_CHECKING:
    from typing import Optional
    from e3.aws.troposphere import Stack


@dataclass(frozen=True)
class Cluster(Construct):
    """Define a Cluster construct.

    :param name: a string that you use to identify your cluster
    :param cluster_settings: The setting to use when creating a cluster. This
        parameter is used to enable CloudWatch Container Insights for a cluster
    :param default_capacity_provider_strategy: The default capacity provider strategy
        for the cluster
    :param tags: The metadata that you apply to the cluster to help you categorize and
        organize them
    """

    name: str
    capacity_providers: Optional[list[str]] = None
    cluster_settings: Optional[list[dict[str, str]]] = None
    default_capacity_provider_strategy: Optional[list[dict[str, str]]] = None
    tags: dict[str, str] = field(default_factory=lambda: {})

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Construct and return ECS cluster troposphere resources."""
        c_settings = None
        if self.cluster_settings:
            c_settings = [ecs.ClusterSetting(**cs) for cs in self.cluster_settings]

        provider_strategy = None
        if self.default_capacity_provider_strategy:
            provider_strategy = [
                ecs.CapacityProviderStrategyItem(**ps)
                for ps in self.default_capacity_provider_strategy
            ]

        kwargs = {
            key: val
            for key, val in {
                "ClusterName": self.name,
                "ClusterSettings": c_settings,
                "CapacityProviders": self.capacity_providers,
                "DefaultCapacityProviderStrategy": provider_strategy,
                "Tags": Tags({"Name": self.name, **self.tags}),
            }.items()
            if val is not None
        }

        return [ecs.Cluster(name_to_id(self.name), **kwargs)]


class ECSPassExecutionRolePolicy(ManagedPolicy):
    """ECSPassExecutionRolePolicy, see description for details."""

    def __init__(self, path: str) -> None:
        """Initialize ECSPassExecutationRolePolicy.

        :param path: path for the managed policy
        """
        super().__init__(
            name="ECSPassExecutionRolePolicy",
            description="Needed to be attached to ECSEventsRole if schedulded"
            "task requires ECSTaskExecutionRole",
            statements=[
                PolicyStatement(
                    effect="Allow",
                    action=["iam:PassRole"],
                    resource=GetAtt(name_to_id("ECSTaskExecutionRole"), "Arn"),
                )
            ],
            path=path,
        )


@dataclass(frozen=True)
class FargateCluster(Cluster):
    """Define a FargateCluster construct.

    :param name: a string that you use to identify your cluster
    :param path: path for IAM resources
    :param tags: The metadata that you apply to the cluster to help you categorize and
        organize them
    """

    name: str
    path: str = "/"
    capacity_providers: Optional[list[str]] = field(default_factory=lambda: ["FARGATE"])
    cluster_settings: Optional[list[dict[str, str]]] = field(
        default_factory=lambda: [{"Name": "containerInsights", "Value": "enabled"}]
    )
    default_capacity_provider_strategy: Optional[list[dict[str, str]]] = field(
        default_factory=lambda: [{"CapacityProvider": "FARGATE", "Weight": "1"}]
    )
    tags: dict[str, str] = field(default_factory=lambda: {})

    @property
    def ecs_task_execution_role(self) -> Role:
        """Return ecs task execution role, see role description for details."""
        # For unknown reason if path is provided for this role it cannot be
        # use by ECS task definitions.
        return Role(
            name="ECSTaskExecutionRole",
            description="grants the Amazon ECS container agent permission to make "
            "AWS API calls on your behalf.",
            trust=Trust(services=["ecs-tasks"]),
            managed_policy_arns=[
                "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
            ],
        )

    @property
    def ecs_events_role(self) -> Role:
        """Return ecs events role, see role description for details."""
        return Role(
            name="ECSEventsRole",
            description="Allow CloudWatch Events service to run Amazon ECS tasks",
            trust=Trust(services=["events"]),
            managed_policy_arns=[
                "arn:aws:iam::aws:policy/service-role/"
                "AmazonEC2ContainerServiceEventsRole",
                Ref(name_to_id("ECSPassExecutionRolePolicy")),
            ],
            path=self.path,
        )

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Construct and return Fargate ECS cluster and associated resources.

        An IAM role for Fargates tasks to be used is also returned.
        """
        return (
            super().resources(stack=stack)
            + ECSPassExecutionRolePolicy(path=self.path).resources(stack=stack)
            + self.ecs_task_execution_role.resources(stack=stack)
            + self.ecs_events_role.resources(stack=stack)
        )
