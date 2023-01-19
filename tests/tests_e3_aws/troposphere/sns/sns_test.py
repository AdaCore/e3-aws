from __future__ import annotations

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
