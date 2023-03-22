from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import Allow

from troposphere import sns, GetAtt, Ref

if TYPE_CHECKING:
    from typing import Any
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack
    from e3.aws.troposphere.awslambda import Function
    from e3.aws.troposphere.iam.policy_statement import ConditionType


class Topic(Construct):
    """A SNS Topic."""

    def __init__(self, name: str, kms_master_key_id: str | None = None):
        """Initialize a SNS Topic.

        :param name: topic name
        :param kms_master_key_id: the ID of an AWS managed customer master
            key (CMK) for Amazon SNS or a custom CMK
        """
        self.name = name
        self.subscriptions: list[sns.Subscription] = []
        self.optional_resources: list[AWSObject] = []
        self.kms_master_key_id = kms_master_key_id

    def add_lambda_subscription(
        self, function: Function, delivery_policy: dict | None = None
    ) -> None:
        """Add a lambda subscription endpoint to topic.

        :param function: lambda function that will be added as endpoint
        :param delivery_policy: The delivery policy to assign to the subscription
        """
        sub_params = {
            "Endpoint": function.arn,
            "Protocol": "lambda",
            "TopicArn": self.arn,
            "DeliveryPolicy": delivery_policy,
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
        self, service: str, name_suffix: str, condition: ConditionType | None = None
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
        params: dict[str, Any] = {}

        if self.kms_master_key_id is not None:
            params["KmsMasterKeyId"] = self.kms_master_key_id

        return [
            sns.Topic(
                name_to_id(self.name),
                TopicName=self.name,
                Subscription=self.subscriptions,
                **params,
            ),
            *self.optional_resources,
        ]
