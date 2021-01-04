"""Provide ECR Repository."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Dict, List

from troposphere import AWSObject, ecr, Tags

from e3.aws import Construct, name_to_id


@dataclass(frozen=True)
class Repository(Construct):
    """Define a ECR Repository construct.

    :param name: name of the repository
    :param tags: An array of key-value pairs to apply to this resource
    """

    name: str
    tags: Dict[str, str] = field(default_factory=lambda: {})

    @property
    def resources(self) -> List[AWSObject]:
        """Construct and return a ECR Repository."""
        return [
            ecr.Repository(
                name_to_id(self.name),
                ImageScanningConfiguration={"scanOnPush": "true"},
                ImageTagMutability="IMMUTABLE",
                RepositoryName=self.name,
                Tags=Tags({"Name": self.name, **self.tags}),
            )
        ]
