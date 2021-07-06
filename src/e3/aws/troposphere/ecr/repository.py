"""Provide ECR Repository."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING


from troposphere import AWSObject, ecr, Tags

from e3.aws import name_to_id
from e3.aws.troposphere import Construct

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack


@dataclass(frozen=True)
class Repository(Construct):
    """Define a ECR Repository construct.

    :param name: name of the repository
    :param tags: An array of key-value pairs to apply to this resource
    """

    name: str
    tags: dict[str, str] = field(default_factory=lambda: {})

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Construct and return a ECR Repository."""
        return [
            ecr.Repository(
                name_to_id(self.name),
                ImageScanningConfiguration=ecr.ImageScanningConfiguration(
                    ScanOnPush=True
                ),
                ImageTagMutability="IMMUTABLE",
                RepositoryName=self.name,
                Tags=Tags({"Name": self.name, **self.tags}),
            )
        ]
