"""Provide fixtures for e3 aws troposphere tests."""

import pytest

from e3.aws.troposphere import Stack


@pytest.fixture
def stack() -> Stack:
    """Stack fixture to help dumping dictionnaries from constructs."""
    return Stack("test-stack", "this is a test stack")
