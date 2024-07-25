from __future__ import annotations

import pytest

from e3.aws.troposphere import Stack
from e3.aws.troposphere.sns import Topic


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
