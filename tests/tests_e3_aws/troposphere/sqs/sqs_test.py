from __future__ import annotations

import pytest

from e3.aws.troposphere import Stack
from e3.aws.troposphere.sqs import Queue

EXPECTED_QUEUE_DEFAULT_TEMPLATE = {
    "Myqueue": {
        "Properties": {"QueueName": "myqueue", "VisibilityTimeout": 30},
        "Type": "AWS::SQS::Queue",
    }
}


EXPECTED_QUEUE_TEMPLATE = {
    "Myqueue": {
        "Properties": {
            "ContentBasedDeduplication": True,
            "FifoQueue": True,
            "QueueName": "myqueue.fifo",
            "RedrivePolicy": {
                "deadLetterTargetArn": {"Fn::GetAtt": ["Somedlqname", "Arn"]},
                "maxReceiveCount": "3",
            },
            "VisibilityTimeout": 10,
        },
        "Type": "AWS::SQS::Queue",
    }
}


EXPECTED_SQS_SUBSCRIPTION_TEMPLATE = {
    "Myqueue": {
        "Properties": {"QueueName": "myqueue", "VisibilityTimeout": 30},
        "Type": "AWS::SQS::Queue",
    },
    "MyqueuePolicy": {
        "Properties": {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Sid": "SomeApplicantWriteAccess",
                        "Action": "sqs:SendMessage",
                        "Condition": {"ArnLike": {"aws:SourceArn": "some_topic_arn"}},
                        "Effect": "Allow",
                        "Principal": {"Service": "sns.amazonaws.com"},
                        "Resource": {"Fn::GetAtt": ["Myqueue", "Arn"]},
                    }
                ],
                "Version": "2012-10-17",
            },
            "Queues": [{"Ref": "Myqueue"}],
        },
        "Type": "AWS::SQS::QueuePolicy",
    },
    "MyqueueSub": {
        "Properties": {
            "Endpoint": {"Fn::GetAtt": ["Myqueue", "Arn"]},
            "Protocol": "sqs",
            "TopicArn": "some_topic_arn",
            "RawMessageDelivery": True,
        },
        "Type": "AWS::SNS::Subscription",
    },
}

EXPECTED_SQS_SUBSCRIPTION_WITH_FILTER_TEMPLATE = {
    "Myqueue": {
        "Properties": {"QueueName": "myqueue", "VisibilityTimeout": 30},
        "Type": "AWS::SQS::Queue",
    },
    "MyqueuePolicy": {
        "Properties": {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Sid": "SomeApplicantWriteAccess",
                        "Action": "sqs:SendMessage",
                        "Condition": {"ArnLike": {"aws:SourceArn": "some_topic_arn"}},
                        "Effect": "Allow",
                        "Principal": {"Service": "sns.amazonaws.com"},
                        "Resource": {"Fn::GetAtt": ["Myqueue", "Arn"]},
                    }
                ],
                "Version": "2012-10-17",
            },
            "Queues": [{"Ref": "Myqueue"}],
        },
        "Type": "AWS::SQS::QueuePolicy",
    },
    "MyqueueSub": {
        "Properties": {
            "Endpoint": {"Fn::GetAtt": ["Myqueue", "Arn"]},
            "Protocol": "sqs",
            "TopicArn": "some_topic_arn",
            "RawMessageDelivery": True,
            "FilterPolicy": {
                "key_a": {
                    "key_b": {
                        "key_c": [
                            "value_1",
                            "value_2",
                        ],
                    },
                },
            },
            "FilterPolicyScope": "MessageBody",
        },
        "Type": "AWS::SNS::Subscription",
    },
}


def test_queue_default(stack: Stack) -> None:
    """Test Queue default creation."""
    stack.add(Queue(name="myqueue"))
    assert stack.export()["Resources"] == EXPECTED_QUEUE_DEFAULT_TEMPLATE


def test_queue(stack: Stack) -> None:
    """Test Queue creation."""
    stack.add(
        Queue(
            name="myqueue", fifo=True, visibility_timeout=10, dlq_name="some_dlq_name"
        )
    )
    assert stack.export()["Resources"] == EXPECTED_QUEUE_TEMPLATE


def test_subscribe_to_sns_topic(stack: Stack) -> None:
    """Test sqs subscription to sns topic."""
    queue = Queue(name="myqueue")
    queue.subscribe_to_sns_topic(topic_arn="some_topic_arn", applicant="SomeApplicant")

    stack.add(queue)

    assert stack.export()["Resources"] == EXPECTED_SQS_SUBSCRIPTION_TEMPLATE


def test_allow_service_to_write_not_unique_sid(stack: Stack) -> None:
    """Test Queue creation with same sid statements in Access Policy."""
    queue = Queue(name="myqueue")
    queue.add_allow_service_to_write_statement(service="sns", applicant="SomeApplicant")
    queue.add_allow_service_to_write_statement(service="s3", applicant="SomeApplicant")

    with pytest.raises(Exception) as ex:
        stack.add(queue)

    assert str(ex.value) == "Unique Sid is required for QueuePolicy statements"


def test_subscribe_to_sns_topic_with_policy_filter(stack: Stack) -> None:
    """Test sqs subscription to sns topic with a policy filter."""
    queue = Queue(name="myqueue")
    queue.subscribe_to_sns_topic(
        topic_arn="some_topic_arn",
        applicant="SomeApplicant",
        filter_policy={"key_a": {"key_b": {"key_c": ["value_1", "value_2"]}}},
        filter_policy_scope="MessageBody",
    )

    stack.add(queue)

    assert stack.export()["Resources"] == EXPECTED_SQS_SUBSCRIPTION_WITH_FILTER_TEMPLATE
