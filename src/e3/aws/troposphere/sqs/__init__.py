from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import Allow

from troposphere import sns, sqs, GetAtt, Ref

if TYPE_CHECKING:
    from typing import Optional
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack
    from e3.aws.troposphere.iam.policy_statement import ConditionType


class Queue(Construct):
    """A SQS Topic."""

    def __init__(
        self,
        name: str,
        fifo: bool = False,
        visibility_timeout: int = 30,
        dlq_name: Optional[str] = None,
    ) -> None:
        """Initialize a SQS.

        :param name: topic name
        :param fifo: Set the queue type to fifo
        :param visibility_timeout: set the length of time during which a message will be
            unavailable after a message is delivered from the queue
        :param dlq_name: dead letter queue name
        """
        self.name = name
        self.attr = {"QueueName": name, "VisibilityTimeout": visibility_timeout}

        if fifo:
            self.attr.update(
                {
                    "FifoQueue": True,
                    "QueueName": f"{name}.fifo",
                    "ContentBasedDeduplication": True,
                }
            )
        if dlq_name:
            self.attr["RedrivePolicy"] = {
                "deadLetterTargetArn": GetAtt(name_to_id(dlq_name), "Arn"),
                "maxReceiveCount": "3",
            }
        self.optional_resources: list[AWSObject] = []

    def allow_service_to_write(
        self, service: str, name_suffix: str, condition: Optional[ConditionType] = None
    ) -> sqs.QueuePolicy:
        """Enable a given service to send a message."""
        return sqs.QueuePolicy(
            name_to_id(f"{self.name}Policy{name_suffix}"),
            Queues=[self.ref],
            PolicyDocument=PolicyDocument(
                statements=[
                    Allow(
                        action="sqs:SendMessage",
                        resource=self.arn,
                        principal={"Service": f"{service}.amazonaws.com"},
                        condition=condition,
                    )
                ]
            ).as_dict,
        )

    def subscribe_to_sns_topic(
        self, topic_arn: str, delivery_policy: dict | None = None
    ) -> None:
        """Subscribe to SNS topic.

        :param topic_arn: ARN of the topic to subscribe
        :param delivery_policy: The delivery policy to assign to the subscription
        """
        sub_params = {
            "Endpoint": self.arn,
            "Protocol": "sqs",
            "TopicArn": topic_arn,
        }

        if delivery_policy:
            sub_params.update({"DeliveryPolicy": delivery_policy})

        queue_sub_policy = self.allow_service_to_write(
            service="sns",
            name_suffix="Sub",
            condition={"ArnLike": {"aws:SourceArn": topic_arn}},
        )

        sub_params.update({"DependsOn": [queue_sub_policy]})

        self.optional_resources.extend(
            [
                sns.SubscriptionResource(name_to_id(f"{self.name}Sub"), **sub_params),
                queue_sub_policy,
            ]
        )

    @property
    def arn(self) -> GetAtt:
        """SQS ARN."""
        return GetAtt(name_to_id(self.name), "Arn")

    @property
    def ref(self) -> Ref:
        """Ref of the SQS."""
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Compute AWS resources for the construct."""
        return [
            sqs.Queue.from_dict(name_to_id(self.name), self.attr),
            *self.optional_resources,
        ]
