from __future__ import annotations
from typing import TYPE_CHECKING
from unittest.mock import patch
from contextlib import contextmanager

if TYPE_CHECKING:
    from typing import Any
    from collections.abc import Iterator

    from e3.aws.troposphere.awslambda import PyFunctionAsset


@contextmanager
def mock_pyfunctionasset() -> Iterator[None]:
    """Mock PyFunctionAsset.

    PyFunctionAsset does a pip install and packaging of source files that
    may be necessary to disable in some tests. With this mock, the checksum
    "dummychecksum" is assigned to assets instead.
    """

    def mock_create_assets_dir(self: PyFunctionAsset, *args: Any, **kargs: Any) -> Any:
        """Disable create_assets_dir and assign a dummy checksum."""
        self.checksum = "dummychecksum"

    with patch(
        "e3.aws.troposphere.awslambda.PyFunctionAsset.create_assets_dir",
        mock_create_assets_dir,
    ):
        yield
