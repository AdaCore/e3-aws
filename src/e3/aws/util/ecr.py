"""Utility functions for AWS ECR service."""

from __future__ import annotations

import base64
import logging
import tempfile
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from e3.fs import sync_tree
from python_on_whales import DockerClient

if TYPE_CHECKING:
    from e3.aws import Session

logger = logging.getLogger("e3.aws.utils.ecr")


def get_ecr_credentials(session: Session) -> tuple[str, str, str]:
    """Get ECR credentials (username, password, registry URL).

    :param session: AWS session to get ECR credentials
    :return: tuple of (username, password, registry URL)
    """
    ecr_client = session.client("ecr")
    ecr_creds = ecr_client.get_authorization_token()["authorizationData"][0]
    ecr_username, ecr_password = (
        base64.b64decode(ecr_creds["authorizationToken"]).decode().split(":", 1)
    )
    ecr_url = ecr_creds["proxyEndpoint"]
    return ecr_username, ecr_password, ecr_url


def build_and_push_image(
    source_dir: str,
    repository_name: str,
    image_tag: str,
    session: Session,
    docker_client: DockerClient | None = None,
    **build_args: Any,
) -> str:
    """Build and push image to an ECR repository and return image URI.

    :param source_dir: directory where to find Dockerfile
    :param repository_name: ECR repository name
    :param image_tag: Docker image tag
    :param session: AWS session to push docker image to ECR
    :param build_args: Keyword arguments to pass to ``docker_client.build``.
        See the ``python-on-whales`` documentation for a complete list of
        possible arguments. Note that this function sets default values for
        some arguments if they are not provided: ``push=True``,
        ``progress="plain"``, ``stream_logs=True``, and ``provenance=False``.
    :param docker_client: Docker client to use for building and pushing.
        This is here in case the user wants to customize the Docker client,
        for example to use podman.
    :raises DockerException: if there is an error building or pushing the image
    :return: image URI
    """
    # Create a Docker client and login to ECR
    if docker_client is None:
        docker_client = DockerClient()
    ecr_username, ecr_password, ecr_url = get_ecr_credentials(session)
    docker_client.login(username=ecr_username, password=ecr_password, server=ecr_url)
    ecr_repo_name = f"{ecr_url.replace('https://', '')}/{repository_name}"
    image_uri = f"{ecr_repo_name}:{image_tag}"

    with tempfile.TemporaryDirectory() as temp_dir:
        sync_tree(source_dir, temp_dir)

        # Set various build args, unless the user has already specified a value
        # Disable provenance to avoid manifest list issues with AWS Lambda
        # See: https://github.com/docker/buildx/issues/1533
        defaults: dict[str, Any] = {
            "push": True,
            "context_path": temp_dir,
            "tags": [image_uri],
            "progress": "plain",
            "stream_logs": True,
            "provenance": False,
        }
        build_args = defaults | build_args

        # Build and push image
        logger.info(f"Building Docker image from {source_dir}")
        logger.debug(f"Build args {build_args}")
        build_result = docker_client.build(**build_args)
        if isinstance(build_result, Iterator):
            # stream_logs=True, causes docker_client.build to return an iterator
            for log_text in build_result:
                logger.debug(log_text)

    return image_uri
