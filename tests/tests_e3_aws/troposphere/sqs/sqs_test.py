from __future__ import annotations

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
    "MyqueuePolicySub": {
        "Properties": {
            "PolicyDocument": {
                "Statement": [
                    {
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
        "DependsOn": [
            "MyqueuePolicySub",
        ],
        "Properties": {
            "Endpoint": {"Fn::GetAtt": ["Myqueue", "Arn"]},
            "Protocol": "sqs",
            "TopicArn": "some_topic_arn",
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
    queue.subscribe_to_sns_topic("some_topic_arn")

    stack.add(queue)

    assert stack.export()["Resources"] == EXPECTED_SQS_SUBSCRIPTION_TEMPLATE
