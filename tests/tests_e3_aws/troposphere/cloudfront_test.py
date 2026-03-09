"""Provide Cloudformation construct tests."""

from __future__ import annotations

import json
from pathlib import Path

from e3.aws.troposphere.cloudfront import S3WebsiteDistribution
from e3.aws.troposphere.s3 import Bucket

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack

TEST_DIR = Path(__file__).resolve().parent


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

    with (TEST_DIR / "s3websitedistribution.json").open() as fd:
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

    with (TEST_DIR / "s3websitedistribution_logging_default.json").open() as fd:
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

    with (TEST_DIR / "s3websitedistribution_logging.json").open() as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_s3_website_distribution_bucket(stack: Stack) -> None:
    """Test Cloudfront S3WebsiteDistribution construct with an external bucket."""
    bucket = Bucket(name="host-bucket")

    s3_website_distribution = S3WebsiteDistribution(
        name="test-s3w-dist",
        aliases=["test.s3w.com"],
        bucket=bucket,
        certificate_arn="acm_arn",
        default_ttl=360,
        lambda_edge_function_arns=["lamba_arn"],
        r53_route_from=[("hosted_zone_id", "test.s3w.com")],
    )

    stack.add(bucket)
    stack.add(s3_website_distribution)

    with (TEST_DIR / "s3websitedistribution_bucket.json").open() as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_s3_website_distribution_iam_path(stack: Stack) -> None:
    """Test Cloudfront S3WebsiteDistribution construct with custom IAM path."""
    stack.add(
        S3WebsiteDistribution(
            name="test-s3w-dist",
            aliases=["test.s3w.com"],
            bucket_name="host-bucket",
            certificate_arn="acm_arn",
            default_ttl=360,
            lambda_edge_function_arns=["lamba_arn"],
            r53_route_from=[("hosted_zone_id", "test.s3w.com")],
            iam_path="/another-path/",
        )
    )

    with (TEST_DIR / "s3websitedistribution_iam_path.json").open() as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_s3_website_distribution_python313(stack: Stack) -> None:
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
            lambda_runtime="python3.13",
        )
    )

    with (TEST_DIR / "s3websitedistribution_py313.json").open() as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template


def test_s3_website_distribution_alias(stack: Stack) -> None:
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
            lambda_runtime="python3.13",
            lambda_version=3,
            lambda_min_version=2,
            lambda_alias="prod",
        )
    )

    with (TEST_DIR / "s3websitedistribution_alias.json").open() as fd:
        expected_template = json.load(fd)

    assert stack.export()["Resources"] == expected_template
