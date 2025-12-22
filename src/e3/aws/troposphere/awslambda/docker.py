from __future__ import annotations
from datetime import timezone, datetime
import logging
from typing import TYPE_CHECKING
from troposphere import awslambda, GetAtt

from e3.aws.troposphere.iam.role import Role
from e3.aws.util.ecr import build_and_push_image
from e3.aws.troposphere.awslambda import Function, Architecture, UnknownPlatform

if TYPE_CHECKING:
    from typing import Any
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack
    from python_on_whales import DockerClient

logger = logging.getLogger(__name__)


class DockerFunction(Function):
    """Lambda using a Docker image."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        source_dir: str,
        repository_name: str,
        image_tag: str,
        timeout: int = 3,
        architecture: Architecture | None = None,
        memory_size: int | None = None,
        logs_retention_in_days: int | None = 731,
        environment: dict[str, str] | None = None,
        logging_config: awslambda.LoggingConfig | None = None,
        dl_config: awslambda.DeadLetterConfig | None = None,
        docker_client: DockerClient | None = None,
        **build_args: Any,
    ):
        """Initialize an AWS lambda function using a Docker image.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param source_dir: directory containing Dockerfile and dependencies
        :param repository_name: ECR repository name
        :param image_tag: docker image version
        :param timeout: maximum execution time (default: 3s)
        :param architecture: x86_64 or arm64. (default: x86_64)
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        :param logs_retention_in_days: The number of days to retain the log
            events in the lambda log group
        :param environment: Environment variables that are accessible from
            function code during execution
        :param logging_config: The function's Amazon CloudWatch Logs settings
        :param dl_config: The dead letter config that specifies the topic or
            queue where lambda sends asynchronous events when they fail processing
        :param docker_client: Docker client to use for building and pushing.
            This is here in case the user wants to customize the Docker client,
            for example to use podman.
        :param build_args: args to pass to docker build
        """
        super().__init__(
            name=name,
            description=description,
            role=role,
            timeout=timeout,
            architecture=architecture,
            memory_size=memory_size,
            logs_retention_in_days=logs_retention_in_days,
            environment=environment,
            logging_config=logging_config,
            dl_config=dl_config,
        )
        self.source_dir: str = source_dir
        self.repository_name: str = repository_name
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S-%f")
        self.image_tag: str = f"{image_tag}-{timestamp}"
        self.image_uri: str | None = None
        self.docker_client = docker_client
        self.build_args = build_args
        if "platforms" not in self.build_args:
            match self.architecture:
                case Architecture.ARM64:
                    self.build_args["platforms"] = ["linux/arm64"]
                case Architecture.X86_64 | None:
                    self.build_args["platforms"] = ["linux/amd64"]
                case _:
                    raise UnknownPlatform(self.architecture)

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Compute AWS resources for the construct.

        Build and push the Docker image to ECR repository.
        Only push ECR image if stack is to be deployed.
        """
        if stack.dry_run:
            self.image_uri = "<dry_run_image_uri>"
        else:
            assert stack.deploy_session is not None
            self.image_uri = build_and_push_image(
                self.source_dir,
                self.repository_name,
                self.image_tag,
                stack.deploy_session,
                push=True,
                docker_client=self.docker_client,
                **self.build_args,
            )

        return self.lambda_resources(image_uri=self.image_uri)
