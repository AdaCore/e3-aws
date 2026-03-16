"""Provide tests for CloudFormation S3 resources."""

from e3.aws.cfn.iam import Allow, PolicyDocument
from e3.aws.cfn.s3 import AccessControl, Bucket, BucketPolicy


def test_create_bucket_policy() -> None:
    """Test bucket policy creation."""
    p = PolicyDocument().append(Allow(to="s3:GetObject", on=["arn:aws:s3:::mybucket"]))
    b = BucketPolicy(name="mypolicy", bucket="mybucket", policy_document=p)
    assert b.properties
    b = BucketPolicy(name="mypolicy", bucket=Bucket(name="mybucket"), policy_document=p)
    assert b.properties


def test_create_bucket() -> None:
    """Test bucket creation."""
    b = Bucket(
        "mybucket",
        access_control=AccessControl.PRIVATE,
        bucket_name="myname",
        versioning=True,
    )
    assert b.properties
