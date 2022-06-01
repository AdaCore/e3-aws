from __future__ import annotations

from datetime import datetime
import logging
import os
from typing import TYPE_CHECKING

from e3.archive import create_archive
from e3.fs import sync_tree, rm
from e3.os.process import Run
from e3.sys import python_script
from troposphere import awslambda, logs, GetAtt, Ref, Sub

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from e3.aws.troposphere.iam.role import Role
from e3.aws.util.ecr import build_and_push_image

if TYPE_CHECKING:
    from typing import Any, Optional, Union
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack

logger = logging.getLogger("e3.aws.troposphere.awslambda")


class Function(Construct):
    """A lambda function."""

    def __init__(
        self,
        name: str,
        description: str,
        role: Union[str, GetAtt, Role],
        code_bucket: Optional[str] = None,
        code_key: Optional[str] = None,
        code_zipfile: Optional[str] = None,
        handler: Optional[str] = None,
        code_version: Optional[int] = None,
        timeout: int = 3,
        runtime: Optional[str] = None,
        memory_size: Optional[int] = None,
        ephemeral_storage_size: Optional[int] = None,
        logs_retention_in_days: Optional[int] = 731,
    ):
        """Initialize an AWS lambda function.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param code_bucket: bucket in which code for the function is found
        :param code_key: key in the previous bucket where the code is stored
        :param code_zipfile: inline code. it is needed when lambda code depends
            on stack informations only known at deployement.
        :param handler: handler name (i.e: entry point)
        :param code_version: code version
        :param timeout: maximum execution time (default: 3s)
        :param runtime: runtime to use
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        :param ephemeral_storage_size: The size of the function’s /tmp directory
            in MB. The default value is 512, but can be any whole number between
            512 and 10240 MB
        :param logs_retention_in_days: The number of days to retain the log events
            in the lambda log group
        """
        self.name = name
        self.description = description
        self.code_bucket = code_bucket
        self.code_key = code_key
        self.code_zipfile = code_zipfile
        self.code_version = code_version
        self.timeout = timeout
        self.runtime = runtime
        self.role = role
        self.handler = handler
        self.memory_size = memory_size
        self.ephemeral_storage_size = ephemeral_storage_size
        self.logs_retention_in_days = logs_retention_in_days

    def cfn_policy_document(self, stack: Stack) -> PolicyDocument:
        statements = [
            PolicyStatement(
                action=[
                    # Needed by CloudFormation to handle the function lifecycle
                    "lambda:CreateFunction",
                    "lambda:GetFunction",
                    "lambda:DeleteFunction",
                    "lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionConfiguration",
                    # Needed by resources referencing the function
                    "lambda:GetFunctionConfiguration",
                ],
                effect="Allow",
                resource=f"arn:aws:lambda:::function:{self.name}*",
            )
        ]
        if isinstance(self.role, GetAtt):
            logger.warning(f"cannot compute needed iam:PassRole for lambda {self.name}")
        else:
            if isinstance(self.role, Role):
                role_arn = f"arn:aws:iam::%(account)s:policy/{self.role.name}"
            else:
                role_arn = self.role

            # Allow user to pass role to the lambda
            statements.append(
                PolicyStatement(
                    action=["iam:PassRole"], effect="Allow", resource=role_arn
                )
            )
        return PolicyDocument(statements=statements)

    @property
    def arn(self) -> GetAtt:
        """Arn of the lambda funtion."""
        return GetAtt(name_to_id(self.name), "Arn")

    @property
    def ref(self) -> Ref:
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        return self.lambda_resources(
            code_bucket=self.code_bucket, code_key=self.code_key
        )

    def lambda_resources(
        self,
        code_bucket: Optional[str] = None,
        code_key: Optional[str] = None,
        image_uri: Optional[str] = None,
    ) -> list[AWSObject]:
        """Return resource associated with the construct.

        :param code_bucket: bucket in which the lambda code is located
        :param code_key: location of the code in the bucket
        :param image_uri: URI of a container image in the Amazon ECR registry
        """
        # If code_bucket and code_key not provided use zipfile if
        # provided.

        params: dict[str, Any] = {}
        if code_bucket is not None and code_key is not None:
            code_params = {"S3Bucket": code_bucket, "S3Key": code_key}
            if self.code_version is not None:
                code_params["S3ObjectVersion"] = str(self.code_version)
        elif self.code_zipfile is not None:
            code_params = {"ZipFile": self.code_zipfile}
        elif image_uri:
            code_params = {"ImageUri": image_uri}
            params["PackageType"] = "Image"

        if isinstance(self.role, Role):
            role = self.role.arn
        else:
            role = self.role

        params.update(
            {
                "Code": awslambda.Code(**code_params),
                "Timeout": self.timeout,
                "Description": self.description,
                "Role": role,
                "FunctionName": self.name,
            }
        )

        if self.runtime is not None:
            params["Runtime"] = self.runtime

        if self.handler is not None:
            params["Handler"] = self.handler

        if self.memory_size is not None:
            params["MemorySize"] = self.memory_size

        if self.ephemeral_storage_size is not None:
            params["EphemeralStorage"] = awslambda.EphemeralStorage(
                Size=self.ephemeral_storage_size
            )

        result = [awslambda.Function(name_to_id(self.name), **params)]
        # If retention duration is given provide a log group.
        # If not provided the lambda creates a log group with
        # infinite retention.
        if self.logs_retention_in_days is not None:
            log_group = logs.LogGroup(
                name_to_id(f"{self.name}LogGroup"),
                DeletionPolicy="Retain",
                LogGroupName=f"/aws/lambda/{self.name}",
                RetentionInDays=self.logs_retention_in_days,
            )
            result.append(log_group)

        return result

    @staticmethod
    def lambda_log_group(lambda_name: str) -> Sub:
        """Return logroup arn for a given lambda.

        :param lambda_name: the lambda name
        """
        return Sub(
            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/"
            + lambda_name
        )

    @staticmethod
    def lambda_log_streams(lambda_name: str) -> Sub:
        """Return arn that matches all logstreams for a lambda log group.

        :param lambda_name: the lambda name
        """
        return Sub(
            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/"
            + lambda_name
            + ":*"
        )

    def invoke_permission(
        self,
        name_suffix: str,
        service: str,
        source_arn: str,
        source_account: Optional[str] = None,
    ) -> awslambda.Permission:
        """Create a Lambda Permission object for a given service.

        :param name_suffix: a suffix used in the object name
        :param service: service name (without amazonaws.com domain name)
        :param source_arn: arn of the resource that can access the lambda
        :param source_account: account that holds the resource. This is
            mandatory only when using S3 as a service as a bucket arn is
            not linked to an account.
        :return: an AWSObject
        """
        params = {
            "Action": "lambda:InvokeFunction",
            "FunctionName": self.ref,
            "Principal": f"{service}.amazonaws.com",
            "SourceArn": source_arn,
        }
        if service == "s3":
            assert source_account is not None
        if source_account is not None:
            params["SourceAccount"] = source_account

        return awslambda.Permission(name_to_id(self.name + name_suffix), **params)


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
        memory_size: Optional[int] = None,
    ):
        """Initialize an AWS lambda function using a Docker image.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param source_dir: directory containing Dockerfile and dependencies
        :param repository_name: ECR repository name
        :param image_tag: docker image version
        :param timeout: maximum execution time (default: 3s)
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        """
        super().__init__(
            name=name,
            description=description,
            role=role,
            timeout=timeout,
            memory_size=memory_size,
        )
        self.source_dir: str = source_dir
        self.repository_name: str = repository_name
        timestamp = datetime.utcnow().strftime("%Y-%m-%d-%H-%M-%S-%f")
        self.image_tag: str = f"{image_tag}-{timestamp}"
        self.image_uri: Optional[str] = None

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
            )

        return self.lambda_resources(image_uri=self.image_uri)


class PyFunction(Function):
    """Lambda with a Python runtime."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        code_dir: str,
        handler: str,
        runtime: str,
        requirement_file: Optional[str] = None,
        code_version: Optional[int] = None,
        timeout: int = 3,
        memory_size: Optional[int] = None,
        ephemeral_storage_size: Optional[int] = None,
        logs_retention_in_days: Optional[int] = 731,
    ):
        """Initialize an AWS lambda function with a Python runtime.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param code_dir: directory containing the python code
        :param handler: name of the function to be invoked on lambda execution
        :param runtime: lambda runtime. It must be a Python runtime.
        :param requirement_file: requirement file for the application code.
            Required packages are automatically fetched (works only from linux)
            and packaged along with the lambda code
        :param code_version: code version
        :param timeout: maximum execution time (default: 3s)
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        :param ephemeral_storage_size: The size of the function’s /tmp directory
            in MB. The default value is 512, but can be any whole number between
            512 and 10240 MB
        :param logs_retention_in_days: The number of days to retain the log events
            in the lambda log group
        """
        assert runtime.startswith("python"), "PyFunction only accept Python runtimes"
        super().__init__(
            name=name,
            description=description,
            code_bucket=None,
            code_key=None,
            role=role,
            handler=handler,
            code_version=code_version,
            timeout=timeout,
            runtime=runtime,
            memory_size=memory_size,
            ephemeral_storage_size=ephemeral_storage_size,
            logs_retention_in_days=logs_retention_in_days,
        )
        self.code_dir = code_dir
        self.requirement_file = requirement_file

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Compute AWS resources for the construct."""
        assert isinstance(stack.s3_bucket, str)
        return self.lambda_resources(
            code_bucket=stack.s3_bucket,
            code_key=f"{stack.s3_key}{self.name}_lambda.zip",
        )

    def populate_package_dir(self, package_dir: str) -> None:
        """Copy user code into lambda package directory.

        :param package_dir: directory in which the package content is put
        """
        # Add lambda code
        sync_tree(self.code_dir, package_dir, delete=False)

    def create_data_dir(self, root_dir: str) -> None:
        """Create data to be pushed to bucket used by cloudformation for resources."""
        # Create directory specific to that lambda
        package_dir = os.path.join(root_dir, name_to_id(self.name), "package")

        # Install the requirements
        if self.requirement_file is not None:
            p = Run(
                python_script("pip")
                + ["install", f"--target={package_dir}", "-r", self.requirement_file],
                output=None,
            )
            assert p.status == 0

        # Copy user code
        self.populate_package_dir(package_dir=package_dir)

        # Create an archive
        create_archive(
            f"{self.name}_lambda.zip",
            from_dir=package_dir,
            dest=root_dir,
            no_root_dir=True,
        )

        # Remove temporary directory
        rm(package_dir, recursive=True)


class Py38Function(PyFunction):
    """Lambda using the Python 3.8 runtime."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        code_dir: str,
        handler: str,
        requirement_file: Optional[str] = None,
        code_version: Optional[int] = None,
        timeout: int = 3,
        memory_size: Optional[int] = None,
        ephemeral_storage_size: Optional[int] = None,
        logs_retention_in_days: Optional[int] = None,
    ):
        """Initialize an AWS lambda function using Python 3.8 runtime.

        See PyFunction for params description.
        """
        super().__init__(
            name=name,
            description=description,
            role=role,
            code_dir=code_dir,
            handler=handler,
            requirement_file=requirement_file,
            code_version=code_version,
            timeout=timeout,
            runtime="python3.8",
            memory_size=memory_size,
            ephemeral_storage_size=ephemeral_storage_size,
            logs_retention_in_days=logs_retention_in_days,
        )
