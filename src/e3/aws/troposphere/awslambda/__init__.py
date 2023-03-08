from __future__ import annotations

from datetime import datetime
import logging
import os
import sys
from typing import TYPE_CHECKING

from e3.archive import create_archive
from e3.fs import sync_tree, rm
from e3.os.process import Run
from troposphere import awslambda, logs, GetAtt, Ref, Sub

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from e3.aws.troposphere.iam.role import Role
from e3.aws.util.ecr import build_and_push_image

if TYPE_CHECKING:
    from typing import Any
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack

logger = logging.getLogger("e3.aws.troposphere.awslambda")


class Function(Construct):
    """A lambda function."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        code_bucket: str | None = None,
        code_key: str | None = None,
        code_zipfile: str | None = None,
        handler: str | None = None,
        code_version: int | None = None,
        timeout: int = 3,
        runtime: str | None = None,
        memory_size: int | None = None,
        ephemeral_storage_size: int | None = None,
        logs_retention_in_days: int | None = 731,
        reserved_concurrent_executions: int | None = None,
        environment: dict[str, str] | None = None,
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
        :param reserved_concurrent_executions: The number of concurrent executions
            that are reserved for this function
        :param environment: Environment variables that are accessible from function
            code during execution
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
        self.reserved_concurrent_executions = reserved_concurrent_executions
        self.environment = environment

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
        code_bucket: str | None = None,
        code_key: str | None = None,
        image_uri: str | None = None,
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
        if self.environment is not None:
            params["Environment"] = awslambda.Environment(Variables=self.environment)

        if self.reserved_concurrent_executions is not None:
            params["ReservedConcurrentExecutions"] = self.reserved_concurrent_executions

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
        source_account: str | None = None,
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
        memory_size: int | None = None,
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
        self.image_uri: str | None = None

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
        requirement_file: str | None = None,
        code_version: int | None = None,
        timeout: int = 3,
        memory_size: int | None = None,
        ephemeral_storage_size: int | None = None,
        logs_retention_in_days: int | None = 731,
        reserved_concurrent_executions: int | None = None,
        environment: dict[str, str] | None = None,
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
        :param reserved_concurrent_executions: The number of concurrent executions
            that are reserved for this function
        :param environment: Environment variables that are accessible from function
            code during execution
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
            reserved_concurrent_executions=reserved_concurrent_executions,
            environment=environment,
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
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    f"--target={package_dir}",
                    "-r",
                    self.requirement_file,
                ],
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
        requirement_file: str | None = None,
        code_version: int | None = None,
        timeout: int = 3,
        memory_size: int | None = None,
        ephemeral_storage_size: int | None = None,
        logs_retention_in_days: int | None = None,
        reserved_concurrent_executions: int | None = None,
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
            reserved_concurrent_executions=reserved_concurrent_executions,
        )


class Alias(Construct):
    """A lambda alias."""

    def __init__(
        self,
        name: str,
        description: str,
        lambda_arn: str | GetAtt | Ref,
        lambda_version: str,
        provisioned_concurrency_config: awslambda.ProvisionedConcurrencyConfiguration
        | None = None,
        routing_config: awslambda.AliasRoutingConfiguration | None = None,
    ):
        """Initialize an AWS lambda alias.

        :param name: function name
        :param description: a description of the function
        :param lambda_arn: the name of the Lambda function
        :param lambda_version: the function version that the alias invokes
        :param provisioned_concurrency_config: specifies a provisioned
            concurrency configuration for a function's alias
        :param routing_config: the routing configuration of the alias
        """
        self.name = name
        self.description = description
        self.lambda_arn = lambda_arn
        self.lambda_version = lambda_version
        self.provisioned_concurrency_config = provisioned_concurrency_config
        self.routing_config = routing_config

    @property
    def ref(self) -> Ref:
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        params = {
            "Name": self.name,
            "Description": self.description,
            "FunctionName": self.lambda_arn,
            "FunctionVersion": self.lambda_version,
        }

        if self.provisioned_concurrency_config is not None:
            params["ProvisionedConcurrencyConfig"] = self.provisioned_concurrency_config

        if self.routing_config is not None:
            params["RoutingConfig"] = self.routing_config

        return [awslambda.Alias(name_to_id(self.name), **params)]


class Version(Construct):
    """A lambda version."""

    def __init__(
        self,
        name: str,
        description: str,
        lambda_arn: str | GetAtt | Ref,
        provisioned_concurrency_config: awslambda.ProvisionedConcurrencyConfiguration
        | None = None,
        code_sha256: str | None = None,
    ):
        """Initialize an AWS lambda version.

        :param name: version name
        :param description: a description for the version to override the description
            in the function configuration. Updates are not supported for this property
        :param lambda_arn: the name of the Lambda function
        :param provisioned_concurrency_config: specifies a provisioned concurrency
            configuration for a function's version. Updates are not supported for this
            property.
        :param code_sha256: only publish a version if the hash value matches the value
            that's specified. Use this option to avoid publishing a version if the
            function code has changed since you last updated it. Updates are not
            supported for this property
        """
        self.name = name
        self.description = description
        self.lambda_arn = lambda_arn
        self.provisioned_concurrency_config = provisioned_concurrency_config
        self.code_sha256 = code_sha256

    @property
    def ref(self) -> Ref:
        return Ref(name_to_id(self.name))

    @property
    def version(self) -> GetAtt:
        """Version of the lambda version."""
        return GetAtt(name_to_id(self.name), "Version")

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        params = {
            "Description": self.description,
            "FunctionName": self.lambda_arn,
        }

        if self.provisioned_concurrency_config is not None:
            params["ProvisionedConcurrencyConfig"] = self.provisioned_concurrency_config

        if self.code_sha256 is not None:
            params["CodeSha256"] = self.code_sha256

        return [awslambda.Version(name_to_id(self.name), **params)]


class AutoVersion(Construct):
    """Automatic lambda versions."""

    def __init__(
        self,
        version: int,
        min_version: int | None = None,
        lambda_name: str | None = None,
        lambda_arn: str | GetAtt | Ref | None = None,
        lambda_function: Function | None = None,
        provisioned_concurrency_config: awslambda.ProvisionedConcurrencyConfiguration
        | None = None,
        code_sha256: str | None = None,
    ) -> None:
        """Create lambda versions from 1 to version included.

        When using this construct, you must provide either a lambda function or
        a lambda name plus arn.

        Parameters provisioned_concurrency_config and code_sha256 are only relevant
        for when creating a new version.

        :param version: number of the latest version
        :param min_version: minimum deployed version (default 1)
        :param lambda_name: the name of the Lambda function
        :param lambda_arn: the arn of the Lambda function
        :param lambda_function: the Lambda function
        :param provisioned_concurrency_config: specifies a provisioned concurrency
            configuration for a function's version. Updates are not supported for this
            property.
        :param code_sha256: only publish a version if the hash value matches the value
            that's specified. Use this option to avoid publishing a version if the
            function code has changed since you last updated it. Updates are not
            supported for this property
        """
        assert version > 0, "version should be greater than 0"
        assert (
            min_version is None or min_version > 0
        ), "min_version should be greater than 0"
        assert (
            min_version is None or min_version <= version
        ), "min_version can't be greater than version"
        assert lambda_function or (
            lambda_name is not None and lambda_arn is not None
        ), "either lambda_function or lambda_name plus lambda_arn should be provided"
        self.version = version
        self.min_version = min_version
        self.lambda_function = lambda_function
        self.lambda_name = lambda_function.name if lambda_function else lambda_name
        self.lambda_arn = lambda_function.arn if lambda_function else lambda_arn
        self.versions = [
            Version(
                name=f"{self.lambda_name}Version{i}",
                description=f"version {i} of {self.lambda_name} lambda",
                lambda_arn=self.lambda_arn,
            )
            for i in range(min_version if min_version is not None else 1, version + 1)
        ]
        self.latest.provisioned_concurrency_config = provisioned_concurrency_config
        self.latest.code_sha256 = code_sha256

    def get_version(self, number: int) -> Version | None:
        """Return a version.

        :param number: version number
        """
        return (
            self.versions[number - 1]
            if number > 0 and number <= len(self.versions)
            else None
        )

    @property
    def previous(self) -> Version:
        """Return the previous version.

        If there is only one version, then the latest version is
        returned.
        """
        # Last item if there is only 1 element
        # Last - 1 item if there is more than 1 elements
        return self.versions[-1] if len(self.versions) < 2 else self.versions[-2]

    @property
    def latest(self) -> Version:
        """Return the latest version."""
        return self.versions[-1]

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        return self.versions


class BlueGreenAliasConfiguration(object):
    """Blue/Green alias configuration."""

    def __init__(
        self,
        version: str,
        name: str | None = None,
        provisioned_concurrency_config: awslambda.ProvisionedConcurrencyConfiguration
        | None = None,
        routing_config: awslambda.AliasRoutingConfiguration | None = None,
    ) -> None:
        """Configure a blue/green alias.

        :param version: lambda version pointed by the alias
        :param name: custom name for the alias
        :param provisioned_concurrency_config: specifies a provisioned
            concurrency configuration for a function's alias
        :param routing_config: the routing configuration of the alias
        """
        self.version = version
        self.name = name
        self.provisioned_concurrency_config = provisioned_concurrency_config
        self.routing_config = routing_config


class BlueGreenAliases(Construct):
    """Blue/Green aliases for a lambda."""

    def __init__(
        self,
        blue_config: BlueGreenAliasConfiguration,
        green_config: BlueGreenAliasConfiguration,
        lambda_name: str | None = None,
        lambda_arn: str | GetAtt | Ref | None = None,
        lambda_function: Function | None = None,
    ) -> None:
        """Create aliases for blue/green deployment of a lambda.

        Blue if the old version of the lambda used in production,
        while green is the new version used in development.

        :param blue_config: configuration for the blue alias
        :param green_config: configuration for the green alias
        :param lambda_name: the name of the Lambda function
        :param lambda_arn: the arn of the Lambda function
        :param lambda_function: the Lambda function
        """
        assert lambda_function or (
            lambda_name is not None and lambda_arn is not None
        ), "either lambda_function or lambda_name plus lambda_arn should be provided"
        self.blue_config = blue_config
        self.green_config = green_config
        self.lambda_function = lambda_function
        self.lambda_name = lambda_function.name if lambda_function else lambda_name
        self.lambda_arn = lambda_function.arn if lambda_function else lambda_arn

        def create_alias(
            config: BlueGreenAliasConfiguration, default_name: str
        ) -> Alias:
            """Return a new alias.

            :param config: alias configuration
            :param default_name: default alias name if none is specified
            """
            name = config.name if config.name is not None else default_name
            return Alias(
                name=name_to_id(f"{self.lambda_name}-{name}-alias"),
                description=f"{name} alias for {self.lambda_name} lambda",
                lambda_arn=self.lambda_arn,
                lambda_version=config.version,
                provisioned_concurrency_config=config.provisioned_concurrency_config,
                routing_config=config.routing_config,
            )

        self.aliases = [
            create_alias(config, default_name)
            for config, default_name in ((blue_config, "blue"), (green_config, "green"))
        ]

    @property
    def blue(self) -> Alias:
        """Return the blue alias."""
        return self.aliases[0]

    @property
    def green(self) -> Alias:
        """Return the green alias."""
        return self.aliases[1]

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        return self.aliases
