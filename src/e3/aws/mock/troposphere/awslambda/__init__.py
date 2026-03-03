"""Provide mock utilities for Lambda troposphere testing."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


@contextmanager
def mock_pyfunctionasset() -> Iterator[None]:
    """Mock PyFunctionAsset.

    PyFunctionAsset does a pip install and packaging of source files that
    may be necessary to disable in some tests. With this mock, the checksum
    "dummychecksum" is assigned to assets instead.
    """
    with patch(
        "e3.aws.troposphere.awslambda.PyFunctionAsset.checksum", "dummychecksum"
    ):
        yield
