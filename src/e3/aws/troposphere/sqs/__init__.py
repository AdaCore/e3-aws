from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import Allow, PolicyStatement

from troposphere import sns, sqs, GetAtt, Ref

if TYPE_CHECKING:
    from typing import Optional
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack
    from e3.aws.troposphere.iam.policy_statement import ConditionType


class Queue(Construct):
    """A SQS Queue."""

    def __init__(
        self,
        name: str,
        fifo: bool = False,
        visibility_timeout: int = 30,
        dlq_name: Optional[str] = None,
    ) -> None:
        """Initialize a SQS.

        :param name: queue name
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
        self.queue_policy_statements: list[PolicyStatement] = []

    def _get_queue_policy_name(self) -> str:
        """Return the QueuePolicy name."""
        return name_to_id(f"{self.name}Policy")

    def add_allow_service_to_write_statement(
        self, service: str, applicant: str, condition: Optional[ConditionType] = None
    ) -> str:
        """Add a statement in QueuePolicy allowing a service to send msg to the queue.

        :param service: service allowed to send message
        :param applicant: applicant name used for the Sid statement
        :param condition: condition to be able to send message
        :return: the QueuePolicy name for depends_on settings
        """
        self.queue_policy_statements.append(
            Allow(
                sid=f"{applicant}WriteAccess",
                action="sqs:SendMessage",
                resource=self.arn,
                principal={"Service": f"{service}.amazonaws.com"},
                condition=condition,
            )
        )
        return self._get_queue_policy_name()

    def subscribe_to_sns_topic(
        self, topic_arn: str, applicant: str, delivery_policy: dict | None = None
    ) -> None:
        """Subscribe to SNS topic.

        :param topic_arn: ARN of the topic to subscribe
        :param applicant: applicant name used for the Sid statement
        :param delivery_policy: The delivery policy to assign to the subscription
        """
        sub_params = {
            "Endpoint": self.arn,
            "Protocol": "sqs",
            "TopicArn": topic_arn,
            "RawMessageDelivery": True,
        }

        if delivery_policy:
            sub_params.update({"DeliveryPolicy": delivery_policy})

        self.add_allow_service_to_write_statement(
            applicant=applicant,
            service="sns",
            condition={"ArnLike": {"aws:SourceArn": topic_arn}},
        )

        self.optional_resources.extend(
            [sns.SubscriptionResource(name_to_id(f"{self.name}Sub"), **sub_params)]
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
        # Add Queue policy to optional resources if any statement
        if self.queue_policy_statements:
            # Check for unique Sid
            check_sid = [statement.sid for statement in self.queue_policy_statements]
            if len(check_sid) != len(set(check_sid)):
                raise Exception("Unique Sid is required for QueuePolicy statements")

            self.optional_resources.extend(
                [
                    sqs.QueuePolicy(
                        self._get_queue_policy_name(),
                        Queues=[self.ref],
                        PolicyDocument=PolicyDocument(
                            statements=self.queue_policy_statements
                        ).as_dict,
                    )
                ]
            )
        return [
            sqs.Queue.from_dict(name_to_id(self.name), self.attr),
            *self.optional_resources,
        ]
