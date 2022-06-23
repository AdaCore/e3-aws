"""Provide S3 construct tests."""
import json
import os

from e3.aws.troposphere.s3.bucket import Bucket, EncryptionAlgorithm
from e3.aws.troposphere.s3 import BucketWithRoles
from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import Py38Function
from e3.aws.troposphere.sns import Topic
from e3.aws.troposphere.sqs import Queue


TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_bucket(stack: Stack) -> None:
    """Test bucket creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    topic_test = Topic(name="test-topic")
    queue_test = Queue(name="test-queue")
    lambda_test = Py38Function(
        name="mypylambda",
        description="this is a test",
        role="somearn",
        code_dir="my_code_dir",
        handler="app.main",
    )

    stack.add(topic_test)
    stack.add(lambda_test)
    stack.add(queue_test)

    bucket = Bucket(name="test-bucket")
    bucket.add_notification_configuration(
        event="s3:ObjectCreated:*", target=topic_test, permission_suffix="TpUpload"
    )
    bucket.add_notification_configuration(
        event="s3:ObjectCreated:*", target=lambda_test, permission_suffix="TpUpload"
    )
    bucket.add_notification_configuration(
        event="s3:ObjectCreated:*", target=queue_test, permission_suffix="FileEvent"
    )
    stack.add(bucket)

    with open(os.path.join(TEST_DIR, "bucket.json")) as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_bucket_with_roles(stack: Stack) -> None:
    """Test BucketWithRoles."""
    bucket = BucketWithRoles(
        name="test-bucket-with-roles",
        iam_names_prefix="TestBucket",
        iam_read_root_name="Restore",
        iam_write_root_name="Push",
        iam_path="/test/",
        trusted_accounts=["123456789"],
    )
    stack.add(bucket)

    with open(os.path.join(TEST_DIR, "bucket-with-roles.json")) as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_bucket_multi_encryption(stack: Stack) -> None:
    """Test bucket accepting multiple types of encryptions and without default."""
    bucket = Bucket(
        name="test-bucket",
        default_bucket_encryption=None,
        authorized_encryptions=[EncryptionAlgorithm.AES256, EncryptionAlgorithm.KMS],
    )
    stack.add(bucket)

    with open(os.path.join(TEST_DIR, "bucket_multi_encryption.json")) as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template
