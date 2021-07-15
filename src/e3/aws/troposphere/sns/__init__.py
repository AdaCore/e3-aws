from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import Allow

from troposphere import sns, GetAtt, Ref

if TYPE_CHECKING:
    from typing import Optional
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack
    from e3.aws.troposphere.awslambda import Function
    from e3.aws.troposphere.iam.policy_statement import ConditionType


class Topic(Construct):
    """A SNS Topic."""

    def __init__(self, name: str):
        """Initialize a SNS Topic.

        :param name: topic name
        """
        self.name = name
        self.subscriptions: list[sns.Subscription] = []
        self.optional_resources: list[AWSObject] = []

    def add_lambda_subscription(
        self, function: Function, delivery_policy: Optional[dict] = None
    ) -> None:
        """Add a lambda subscription endpoint to topic.

        :param function: lambda function that will be added as endpoint
        :param delivery_policy: The delivery policy to assign to the subscription
        """
        sub_params = {
            key: val
            for key, val in {
                "Endpoint": function.arn,
                "Protocol": "lambda",
                "TopicArn": self.arn,
                "DeliveryPolicy": delivery_policy,
            }.items()
        }

        self.optional_resources.extend(
            [
                sns.SubscriptionResource(
                    name_to_id(f"{function.name}Sub"), **sub_params
                ),
                function.invoke_permission(
                    name_suffix=self.name, service="sns", source_arn=self.arn
                ),
            ]
        )

    def allow_publish_policy(
        self, service: str, name_suffix: str, condition: Optional[ConditionType] = None
    ) -> sns.TopicPolicy:
        """Return a policy allowing a service to publish to the topic.

        :param service: service allowed to publish
        :param name_suffix: a suffix used in the object name
        :param condition: condition to be able to publish
        """
        return sns.TopicPolicy(
            name_to_id(f"{self.name}Policy{name_suffix}"),
            Topics=[self.ref],
            PolicyDocument=PolicyDocument(
                statements=[
                    Allow(
                        action="sns:Publish",
                        resource=self.ref,
                        principal={"Service": f"{service}.amazonaws.com"},
                        condition=condition,
                    )
                ]
            ).as_dict,
        )

    @property
    def arn(self) -> GetAtt:
        """Arn of the SNS Topic."""
        return self.ref

    @property
    def ref(self) -> Ref:
        """Ref of the SNS Topic."""
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Compute AWS resources for the construct."""
        return [
            sns.Topic(
                name_to_id(self.name),
                TopicName=self.name,
                Subscription=self.subscriptions,
            ),
            *self.optional_resources,
        ]
