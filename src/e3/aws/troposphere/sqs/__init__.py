from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import Allow

from troposphere import sqs, GetAtt, Ref

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
        return [sqs.Queue.from_dict(name_to_id(self.name), self.attr)]
