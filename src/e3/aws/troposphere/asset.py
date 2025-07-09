from __future__ import annotations
from typing import TYPE_CHECKING
from abc import abstractmethod

from e3.aws.troposphere import Construct

if TYPE_CHECKING:
    from troposphere import AWSObject

    from e3.aws.troposphere import Stack


class Asset(Construct):
    """Generic asset."""

    @property
    @abstractmethod
    def s3_key(self) -> str:
        """Return the S3 key of this asset."""
        ...

    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
        """Return no resources."""
        return []
