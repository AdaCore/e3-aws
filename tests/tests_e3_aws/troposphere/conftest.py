"""Provide fixtures for e3 aws troposphere tests."""

from __future__ import annotations
from typing import TYPE_CHECKING
import pytest
from tempfile import TemporaryDirectory

from e3.aws.troposphere import Stack
from e3.aws.mock.troposphere.awslambda import mock_pyfunctionasset


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def stack() -> Iterator[Stack]:
    """Stack fixture to help dumping dictionnaries from constructs."""
    with TemporaryDirectory() as tmpd, mock_pyfunctionasset():
        yield Stack(
            "test-stack",
            "this is a test stack",
            s3_bucket="cfn_bucket",
            s3_key="templates/",
            s3_assets_key="assets/",
            # It's required to assign gen_assets_dir in order to trigger
            # create_assets_dir
            gen_assets_dir=tmpd,
        )
