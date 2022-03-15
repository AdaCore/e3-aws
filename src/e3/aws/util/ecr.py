"""Utility functions for AWS ECR service."""

from __future__ import annotations

import base64
import logging
import tempfile
from typing import TYPE_CHECKING

import docker
from e3.fs import sync_tree, rm

if TYPE_CHECKING:
    from e3.aws import Session

logger = logging.getLogger("e3.aws.utils.ecr")


def build_and_push_image(
    source_dir: str, repository_name: str, image_tag: str, session: Session
) -> str:
    """Build and push image to an ECR repository and return image URI.

    :param source_dir: directory where to find Dockerfile
    :param repository_name: ECR repository name
    :param image_tag: Docker image tag
    :param session: AWS session to push docker image to ECR
    """
    temp_dir = tempfile.mkdtemp()
    try:
        sync_tree(source_dir, temp_dir)

        docker_client = docker.from_env()
        # Build image
        image, build_log = docker_client.images.build(
            path=temp_dir, tag=f"{repository_name}:{image_tag}", rm=True
        )
        logging.info(f"Building Docker image from {source_dir}")
        for chunk in build_log:
            if "stream" in chunk:
                for line in chunk["stream"].splitlines():
                    logging.debug(line)

        # Push image to registry
        ecr_client = session.client("ecr")
        ecr_creds = ecr_client.get_authorization_token()["authorizationData"][0]
        ecr_username, ecr_password = (
            base64.b64decode(ecr_creds["authorizationToken"])
            .decode("utf-8")
            .split(":", 1)
        )
        ecr_url = ecr_creds["proxyEndpoint"]
        docker_client.login(
            username=ecr_username, password=ecr_password, registry=ecr_url
        )
        ecr_repo_name = f"{ecr_url.replace('https://', '')}/{repository_name}"
        image.tag(ecr_repo_name, tag=image_tag)

        push_log = docker_client.images.push(ecr_repo_name, tag=image_tag)
        logging.info(f"Pushing Docker image to {ecr_repo_name} with tag {image_tag}")
        logging.debug(push_log)

        image_uri = f"{ecr_repo_name}:{image_tag}"

    finally:
        rm(temp_dir, recursive=True)

    return image_uri
