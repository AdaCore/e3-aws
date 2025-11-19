from __future__ import annotations
from typing import TYPE_CHECKING
import pytest

from e3.aws.troposphere import Stack
from e3.aws.troposphere.sns import Topic
from e3.aws.troposphere.awslambda import PyFunction, Version, Alias

if TYPE_CHECKING:
    from typing import Any


EXPECTED_TOPIC_DEFAULT_TEMPLATE = {
    "Mytopic": {
        "Properties": {"Subscription": [], "TopicName": "mytopic"},
        "Type": "AWS::SNS::Topic",
    }
}


EXPECTED_TOPIC_TEMPLATE = {
    "Mytopic": {
        "Properties": {
            "Subscription": [],
            "TopicName": "mytopic",
            "KmsMasterKeyId": "arn:aws:kms:eu-west-1:012345678901:key/"
            "00000000-0000-0000-0000-000000000000",
        },
        "Type": "AWS::SNS::Topic",
    }
}


def test_topic_default(stack: Stack) -> None:
    """Test Topic default creation."""
    stack.add(Topic(name="mytopic"))
    assert stack.export()["Resources"] == EXPECTED_TOPIC_DEFAULT_TEMPLATE


def test_topic(stack: Stack) -> None:
    """Test Topic creation."""
    stack.add(
        Topic(
            name="mytopic",
            kms_master_key_id="arn:aws:kms:eu-west-1:012345678901:key/"
            "00000000-0000-0000-0000-000000000000",
        )
    )
    assert stack.export()["Resources"] == EXPECTED_TOPIC_TEMPLATE


def test_allow_service_to_publish_not_unique_sid(stack: Stack) -> None:
    """Test topic creation with same Sid statements in Access Policy."""
    topic = Topic("mytopic")
    topic.add_allow_service_to_publish_statement(
        applicant="SomeApplicant",
        service="s3",
    )
    topic.add_allow_service_to_publish_statement(
        applicant="SomeApplicant",
        service="lambda",
    )

    with pytest.raises(Exception) as ex:
        stack.add(topic)

    assert str(ex.value) == "Unique Sid is required for TopicPolicy statements"


@pytest.mark.parametrize(
    "version, expected_endpoint, expected_function_name_ref",
    [
        # Add the subscription to the function itself
        (
            None,
            {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "Mypylambda",
        ),
        # Add the subscription to a version of the function
        (
            Version(
                name="myversion", description="this is some version", lambda_arn=""
            ),
            {"Ref": "Myversion"},
            "Myversion",
        ),
        # Add the subscription to an alias of the function
        (
            Alias(
                name="myalias",
                description="this is some alias",
                lambda_arn="",
                lambda_version="",
            ),
            {"Ref": "Myalias"},
            "Myalias",
        ),
    ],
)
def test_topic_lambda_subscription(
    version: Version | Alias | None,
    expected_endpoint: dict[str, Any],
    expected_function_name_ref: str,
    stack: Stack,
) -> None:
    """Test topic creation with lambda subscription.

    :param version: a version or alias of the function
    :param expected_endpoint: value that should be set for Endpoint
    :param expected_function_name_ref: name that should be referenced in FunctionName
    :param stack: the stack
    """
    topic = Topic("mytopic")
    topic.add_lambda_subscription(
        function=PyFunction(
            name="mypylambda",
            description="this is a test",
            role="somearn",
            runtime="python3.9",
            code_dir="my_code_dir",
            handler="app.main",
        ),
        version=version,
    )
    stack.add(topic)
    assert stack.export()["Resources"] == EXPECTED_TOPIC_DEFAULT_TEMPLATE | {
        f"{expected_function_name_ref}Sub": {
            "Properties": {
                "Endpoint": expected_endpoint,
                "Protocol": "lambda",
                "TopicArn": {
                    "Ref": "Mytopic",
                },
            },
            "Type": "AWS::SNS::Subscription",
        },
        f"{expected_function_name_ref}mytopic": {
            "Properties": {
                "Action": "lambda:InvokeFunction",
                "FunctionName": {
                    "Ref": expected_function_name_ref,
                },
                "Principal": "sns.amazonaws.com",
                "SourceArn": {
                    "Ref": "Mytopic",
                },
            },
            "Type": "AWS::Lambda::Permission",
        },
    }
