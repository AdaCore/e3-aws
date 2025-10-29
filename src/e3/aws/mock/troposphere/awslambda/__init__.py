from __future__ import annotations
from typing import TYPE_CHECKING
from unittest.mock import patch
from contextlib import contextmanager

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
