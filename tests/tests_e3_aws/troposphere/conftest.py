"""Provide fixtures for e3 aws troposphere tests."""

import pytest

from e3.aws import Session, Stack


@pytest.fixture
def stack() -> Stack:
    """Stack fixture to help dumping dictionnaries from constructs."""
    return Stack("test-stack", Session(regions=["eu-west-1"]), opts=None)
