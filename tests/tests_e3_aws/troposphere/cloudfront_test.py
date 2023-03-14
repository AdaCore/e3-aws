"""Provide Cloudformation construct tests."""
from __future__ import annotations
import json
import os

from e3.aws.troposphere import Stack
from e3.aws.troposphere.s3 import Bucket
from e3.aws.troposphere.cloudfront import S3WebsiteDistribution


TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_s3_website_distribution(stack: Stack) -> None:
    """Test Cloudfront S3WebsiteDistribution construct."""
    stack.add(
        S3WebsiteDistribution(
            name="test-s3w-dist",
            aliases=["test.s3w.com"],
            bucket_name="host-bucket",
            certificate_arn="acm_arn",
            default_ttl=360,
            lambda_edge_function_arns=["lamba_arn"],
            r53_route_from=[("hosted_zone_id", "test.s3w.com")],
        )
    )

    with open(os.path.join(TEST_DIR, "s3websitedistribution.json")) as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_s3_website_distribution_logging_default(stack: Stack) -> None:
    """Test Cloudfront S3WebsiteDistribution construct with default logging."""
    bucket = Bucket(name="test-bucket")

    stack.add(
        S3WebsiteDistribution(
            name="test-s3w-dist",
            aliases=["test.s3w.com"],
            bucket_name="host-bucket",
            certificate_arn="acm_arn",
            default_ttl=360,
            lambda_edge_function_arns=["lamba_arn"],
            r53_route_from=[("hosted_zone_id", "test.s3w.com")],
            logging_bucket=bucket.domain_name,
        )
    )

    with open(
        os.path.join(TEST_DIR, "s3websitedistribution_logging_default.json")
    ) as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_s3_website_distribution_logging(stack: Stack) -> None:
    """Test Cloudfront S3WebsiteDistribution construct with logging."""
    bucket = Bucket(name="test-bucket")

    stack.add(
        S3WebsiteDistribution(
            name="test-s3w-dist",
            aliases=["test.s3w.com"],
            bucket_name="host-bucket",
            certificate_arn="acm_arn",
            default_ttl=360,
            lambda_edge_function_arns=["lamba_arn"],
            r53_route_from=[("hosted_zone_id", "test.s3w.com")],
            logging_bucket=bucket.regional_domain_name,
            logging_prefix="myprefix",
            logging_include_cookies=True,
        )
    )

    with open(os.path.join(TEST_DIR, "s3websitedistribution_logging.json")) as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template
