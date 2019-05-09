from e3.aws.cfn import AWSType, Resource
import re


class Repository(Resource):
    """CodeCommit Repository."""

    ATTRIBUTES = ("Arn", "CloneUrlHttp", "CloneUrlSsh", "Name")

    def __init__(self, name, description):
        """Initialize a Repository.

        :param name: name of the repository
        :type name: str
        :param description: description of the repository content
        :type description: str
        """
        resource_name = re.sub(r"[^a-zA-Z0-9]+", "", name)
        super(Repository, self).__init__(
            resource_name, kind=AWSType.CODE_COMMIT_REPOSITORY
        )
        self.name = resource_name
        self.repository_name = name
        self.description = description

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        return {
            "RepositoryName": self.repository_name,
            "RepositoryDescription": self.description,
        }
