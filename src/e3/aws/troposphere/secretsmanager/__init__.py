from __future__ import annotations
from typing import TYPE_CHECKING

from e3.aws.troposphere import Construct, Stack, name_to_id
from e3.aws.troposphere.iam.managed_policy import ManagedPolicy
from e3.aws.troposphere.iam.policy_statement import Allow

from troposphere import secretsmanager, Ref

if TYPE_CHECKING:
    from troposphere import AWSObject
    from e3.aws.troposphere.awslambda import Function


class Secret(Construct):
    """Provide Secret resource and associated utility methods."""

    def __init__(self, name: str, description: str):
        """Initialize a Secret instance.

        :param name: name of the secret
        :param description: secret description
        """
        self.name = name
        self.description = description
        self.secret = secretsmanager.Secret(
            name_to_id(name), Description=description, Name=name
        )

    @property
    def rotation_lambda_policy(self) -> ManagedPolicy:
        """Return policy granting permissions to rotate the secret."""
        return ManagedPolicy(
            name=f"{self.name}RotationPolicy",
            description="Managed policy granting permissions"
            f"to rotate the {self.name} secret",
            statements=[
                Allow(
                    action=[
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:UpdateSecretVersionStage",
                    ],
                    resource=self.secret_arn,
                )
            ],
        )

    @property
    def secret_arn(self) -> str:
        """Return secret arn."""
        return Ref(self.secret)

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return troposphere objects associated with the construct."""
        return [self.secret]


class RotationSchedule(Construct):
    """Provide resources to schedule rotation for a secret."""

    def __init__(
        self, secret: Secret, rotation_function: Function, schedule_expression: str
    ):
        """Initialize a ScheduleRotationSecret instance.

        :param secret: secret to rotate
        :param rotation_function: lambda function that rotates the secret
        :param schedule_expression: expression that schedule the rotation.
            It has to follow the scheduled event rules format
            https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html
        """
        self.schedule_expression = schedule_expression
        self.lambda_permission = rotation_function.invoke_permission(
            name_suffix="permission",
            service="secretsmanager",
            source_arn=secret.secret_arn,
        )
        self.schedule = secretsmanager.RotationSchedule(
            name_to_id(f"{secret.name}RotationSchedule"),
            RotationLambdaARN=rotation_function.arn,
            RotationRules=secretsmanager.RotationRules(
                ScheduleExpression=schedule_expression
            ),
            SecretId=secret.secret_arn,
            DependsOn=self.lambda_permission.title,
        )

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return troposphere objects associated with the construct."""
        return [self.lambda_permission, self.schedule]
