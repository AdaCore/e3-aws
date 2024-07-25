from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import Allow, PolicyStatement

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
        self.topic_policy_statements: list[PolicyStatement] = []

    def _get_topic_policy_name(self) -> str:
        """Return the TopicPolicy name."""
        return name_to_id(f"{self.name}Policy")

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
        }

        if delivery_policy:
            sub_params.update({"DeliveryPolicy": delivery_policy})

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

    def add_allow_service_to_publish_statement(
        self, service: str, applicant: str, condition: ConditionType | None = None
    ) -> str:
        """Add a statement in TopicPolicy allowing a service to publish to the topic.

        :param service: service allowed to publish
        :param applicant: applicant name used for the Sid statement
        :param condition: condition to be able to publish
        :return: the TopicPolicy name for depends_on settings
        """
        self.topic_policy_statements.append(
            Allow(
                sid=f"{applicant}PubAccess",
                action="sns:Publish",
                resource=self.ref,
                principal={"Service": f"{service}.amazonaws.com"},
                condition=condition,
            )
        )
        return self._get_topic_policy_name()

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

        # Add Topic policy to optional resources if any statement
        if self.topic_policy_statements:
            # Check for unique Sid
            check_sid = [statement.sid for statement in self.topic_policy_statements]
            if len(check_sid) != len(set(check_sid)):
                raise Exception("Unique Sid is required for TopicPolicy statements")

            self.optional_resources.extend(
                [
                    sns.TopicPolicy(
                        self._get_topic_policy_name(),
                        Topics=[self.ref],
                        PolicyDocument=PolicyDocument(
                            statements=self.topic_policy_statements,
                        ).as_dict,
                    )
                ]
            )

        return [
            sns.Topic(
                name_to_id(self.name),
                TopicName=self.name,
                Subscription=self.subscriptions,
                **params,
            ),
            *self.optional_resources,
        ]
