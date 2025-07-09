from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws.cfn import AWSType, Resource
import re

if TYPE_CHECKING:
    from typing import Any


class Repository(Resource):
    """CodeCommit Repository."""

    ATTRIBUTES = ("Arn", "CloneUrlHttp", "CloneUrlSsh", "Name")

    def __init__(self, name: str, description: str) -> None:
        """Initialize a Repository.

        :param name: name of the repository
        :param description: description of the repository content
        """
        resource_name = re.sub(r"[^a-zA-Z0-9]+", "", name)
        super(Repository, self).__init__(
            resource_name, kind=AWSType.CODE_COMMIT_REPOSITORY
        )
        self.name = resource_name
        self.repository_name = name
        self.description = description

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        return {
            "RepositoryName": self.repository_name,
            "RepositoryDescription": self.description,
        }
