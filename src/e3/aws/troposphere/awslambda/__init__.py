from __future__ import annotations

from datetime import datetime
import logging
import os
import sys
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING
from zipfile import ZipFile
from hashlib import sha256
import difflib
import zipfile
from functools import cached_property
import botocore.exceptions

from e3.archive import create_archive
from e3.fs import sync_tree, rm, mv
from e3.os.process import Run
from e3.net.http import HTTPSession
from troposphere import awslambda, logs, GetAtt, Ref, Sub

from e3.aws import name_to_id
from e3.aws.cfn import client
from e3.aws.troposphere import Construct, Asset
from e3.aws.troposphere.asset import AssetLayout
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from e3.aws.troposphere.iam.role import Role
from e3.aws.util.ecr import build_and_push_image
from e3.aws.util import color_diff, modified_diff_lines

if TYPE_CHECKING:
    from typing import Any, Callable
    from troposphere import AWSObject
    import botocore.client
    from e3.aws.troposphere import Stack

logger = logging.getLogger("e3.aws.troposphere.awslambda")


def package_pyfunction_code(
    filename: str,
    /,
    package_dir: str,
    root_dir: str,
    populate_package_dir: Callable[[str], None],
    runtime: str | None = None,
    requirement_file: str | None = None,
) -> None:
    """Package user code with dependencies.

    :param filename: name of the archive
    :param package_dir: temporary packaging directory
    :param root_dir: destination directory for the archive
    :param populate_package_dir: callback to populate the package directory with
        extra code
    :param runtime: the Python runtime
    :param requirement_file: the list of Python dependencies
    """
    # Install the requirements
    if requirement_file is not None:
        assert runtime is not None
        runtime_config = PyFunction.RUNTIME_CONFIGS[runtime]
        p = Run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                f"--python-version={runtime.lstrip('python')}",
                *(f"--platform={platform}" for platform in runtime_config["platforms"]),
                f"--implementation={runtime_config['implementation']}",
                "--only-binary=:all:",
                f"--target={package_dir}",
                "-r",
                requirement_file,
            ],
            output=None,
        )
        assert p.status == 0

    # Populate the package directory with extra code
    if populate_package_dir is not None:
        populate_package_dir(package_dir)

    # Create an archive
    create_archive(
        filename,
        from_dir=package_dir,
        dest=root_dir,
        no_root_dir=True,
    )

    # Remove the temporary directory
    rm(package_dir, recursive=True)


class PyFunctionAsset(Asset):
    """PyFunction code packaged with dependencies in a ZIP archive."""

    def __init__(
        self,
        name: str,
        *,
        code_dir: str,
        runtime: str,
        requirement_file: str | None = None,
        layout: AssetLayout = AssetLayout.TREE,
    ) -> None:
        """Initialize PyFunctionAsset.

        :param name: name of the archive
        :param code_dir: directory that contains the Python code
        :param runtime: the Python runtime
        :param requirement_file: the list of Python dependencies
        :param layout: the layout for this asset
        """
        super().__init__(name)
        self.code_dir = code_dir
        self.runtime = runtime
        self.requirement_file = requirement_file
        self.layout = layout

        # Temporary directory where the archive is created
        self._archive_tmpd: TemporaryDirectory | None = None
        self._archive_dir: str | None = None

    def __enter__(self) -> PyFunctionAsset:
        """Create a temporary archive directory."""
        if self._archive_dir is None:
            self._archive_tmpd = TemporaryDirectory()
            self._archive_dir = self._archive_tmpd.__enter__()

        return self

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        """Delete the temporary archive directory."""
        if self._archive_tmpd is not None:
            self._archive_tmpd.__exit__(*args, **kwargs)

        self._archive_dir = None
        self._archive_tmpd = None

    @cached_property
    def checksum(self) -> str:
        """Package the asset and return the checksum of the archive.

        All .pyc files are excluded as they are not reproducible.

        :return: the checksum
        """
        # Ensure the temporary directory exists
        if self._archive_dir is None:
            self.__enter__()

        assert self._archive_dir is not None

        # Create a temporary packaging directory
        package_dir = os.path.join(self._archive_dir, "package")

        # Package the code with dependencies
        raw_archive_name = f"{self.name}.zip"
        package_pyfunction_code(
            raw_archive_name,
            package_dir=package_dir,
            root_dir=self._archive_dir,
            populate_package_dir=self.populate_package_dir,
            runtime=self.runtime,
            requirement_file=self.requirement_file,
        )

        raw_archive_path = os.path.abspath(
            os.path.join(self._archive_dir, raw_archive_name)
        )

        # Compute the checksum
        sha = sha256()
        with ZipFile(raw_archive_path) as zipfd:
            for zip_info in sorted(
                zipfd.infolist(), key=lambda zip_info: zip_info.filename
            ):
                if zip_info.is_dir():
                    content = b""
                elif not zip_info.filename.endswith(".pyc"):
                    with zipfd.open(zip_info) as f:
                        content = f.read()
                else:
                    continue

                sha.update(zip_info.filename.encode())
                sha.update(content)

        checksum = sha.hexdigest()

        # Rename the archive with the checksum
        archive_path = os.path.join(self._archive_dir, f"{self.name}_{checksum}.zip")
        mv(raw_archive_path, archive_path)

        return checksum

    @cached_property
    def archive_path(self) -> str:
        """Return the path of the archive with the checksum."""
        assert self._archive_dir is not None
        return os.path.join(self._archive_dir, self.archive_name)

    @cached_property
    def archive_name(self) -> str:
        """Return the name of the archive with the checksum."""
        return f"{self.name}_{self.checksum}.zip"

    @cached_property
    def s3_key(self) -> str:
        """Return a unique S3 key with the checksum of the package."""
        return (
            f"{self.name}/{self.archive_name}"
            if self.layout == AssetLayout.TREE
            else self.archive_name
        )

    def populate_package_dir(self, package_dir: str) -> None:
        """Copy user code into package directory.

        :param package_dir: directory in which the package content is put
        """
        # Add lambda code
        sync_tree(self.code_dir, package_dir, delete=False)

    def upload(
        self,
        s3_bucket: str,
        s3_root_key: str,
        client: botocore.client.S3 | None = None,
        dry_run: bool | None = None,
    ) -> None:
        if self._archive_dir is not None:
            self._upload_file(
                s3_bucket=s3_bucket,
                s3_key=f"{s3_root_key}{self.s3_key}",
                root_dir=self._archive_dir,
                file=self.archive_path,
                client=client,
                check_exists=True,
                dry_run=dry_run,
            )


class Function(Construct):
    """A lambda function."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        version: int | Version | AutoVersion | None = None,
        min_version: int | None = None,
        alias: str | Alias | BlueGreenAliases | None = None,
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
        logging_config: awslambda.LoggingConfig | None = None,
        dl_config: awslambda.DeadLetterConfig | None = None,
        vpc_config: awslambda.VPCConfig | None = None,
    ):
        """Initialize an AWS lambda function.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param version: the latest deployed version
        :param min_version: minimum deployed version (default 1)
        :param alias: alias for the latest version
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
        :param logging_config: The function's Amazon CloudWatch Logs settings
        :param dl_config: The dead letter config that specifies the topic or queue where
            lambda sends asynchronous events when they fail processing
        :param vpc_config: For network connectivity to AWS resources in a VPC, specify
            a list of security groups and subnets in the VPC. When you connect a
            function to a VPC, it can access resources and the internet only
            through that VPC
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
        self.logging_config = logging_config
        self.dl_config = dl_config
        self.vpc_config = vpc_config

        self.version: Version | AutoVersion | None = None
        self.alias: Alias | BlueGreenAliases | None = None
        if version is not None:
            if isinstance(version, (Version, AutoVersion)):
                self.version = version
            else:
                self.version = AutoVersion(
                    version=version,
                    min_version=min_version,
                    lambda_name=name,
                    lambda_arn=self.arn,
                )

            if alias is not None:
                if isinstance(alias, (Alias, BlueGreenAliases)):
                    self.alias = alias
                else:
                    self.alias = Alias(
                        name_to_id(f"{name}-{alias}"),
                        description=f"{name_to_id(alias)} version of {name}",
                        lambda_arn=self.arn,
                        lambda_version=(
                            self.version
                            if isinstance(self.version, Version)
                            else self.version.latest
                        ),
                        alias_name=alias,
                    )

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

        if self.logging_config is not None:
            params["LoggingConfig"] = self.logging_config

        if self.dl_config is not None:
            params["DeadLetterConfig"] = self.dl_config

        if self.vpc_config is not None:
            params["VpcConfig"] = self.vpc_config

        result = [awslambda.Function(name_to_id(self.name), **params)]
        # If retention duration is given provide a log group.
        # If not provided the lambda creates a log group with
        # infinite retention.
        if self.logs_retention_in_days is not None:
            log_group = logs.LogGroup(
                name_to_id(f"{self.name}LogGroup"),
                DeletionPolicy="Retain",
                UpdateReplacePolicy="Retain",
                LogGroupName=f"/aws/lambda/{self.name}",
                RetentionInDays=self.logs_retention_in_days,
            )
            result.append(log_group)

        if self.version is not None:
            versions = (
                self.version.versions
                if isinstance(self.version, AutoVersion)
                else [self.version]
            )
            result.extend(
                [
                    awslambda.Version(
                        name_to_id(version.name),
                        **version.as_dict,
                        FunctionName=self.arn,
                    )
                    for version in versions
                ]
            )

        if self.alias is not None:
            aliases = (
                self.alias.aliases
                if isinstance(self.alias, BlueGreenAliases)
                else [self.alias]
            )
            result.extend(
                [
                    awslambda.Alias(
                        name_to_id(alias.name),
                        **alias.as_dict,
                        FunctionName=self.arn,
                    )
                    for alias in aliases
                ]
            )

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
        version: Version | Alias | None = None,
    ) -> awslambda.Permission:
        """Create a Lambda Permission object for a given service.

        :param name_suffix: a suffix used in the object name
        :param service: service name (without amazonaws.com domain name)
        :param source_arn: arn of the resource that can access the lambda
        :param source_account: account that holds the resource. This is
            mandatory only when using S3 as a service as a bucket arn is
            not linked to an account.
        :param version: specific version or alias to give permission for
        :return: an AWSObject
        """
        target = version if version is not None else self

        params = {
            "Action": "lambda:InvokeFunction",
            "FunctionName": target.ref,
            "Principal": f"{service}.amazonaws.com",
            "SourceArn": source_arn,
        }
        if service == "s3":
            assert source_account is not None
        if source_account is not None:
            params["SourceAccount"] = source_account

        return awslambda.Permission(name_to_id(target.name + name_suffix), **params)


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
        logging_config: awslambda.LoggingConfig | None = None,
        dl_config: awslambda.DeadLetterConfig | None = None,
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
        :param logging_config: The function's Amazon CloudWatch Logs settings
        :param dl_config: The dead letter config that specifies the topic or queue where
            lambda sends asynchronous events when they fail processing
        """
        super().__init__(
            name=name,
            description=description,
            role=role,
            timeout=timeout,
            memory_size=memory_size,
            logging_config=logging_config,
            dl_config=dl_config,
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

    AMAZON_LINUX_2_RUNTIMES = ("3.9", "3.10", "3.11")
    AMAZON_LINUX_2023_RUNTIMES = ("3.12", "3.13")
    RUNTIME_CONFIGS = {
        f"python{version}": {
            "implementation": "cp",
            # Amazon Linux 2 glibc version is 2.26 and we support only x86_64
            # architecture for now.
            "platforms": ("manylinux_2_17_x86_64", "manylinux_2_24_x86_64"),
        }
        for version in AMAZON_LINUX_2_RUNTIMES
    }
    RUNTIME_CONFIGS.update(
        {
            f"python{version}": {
                "implementation": "cp",
                # Amazon Linux 2023 glibc version is 2.34
                "platforms": (
                    "manylinux_2_17_x86_64",
                    "manylinux_2_24_x86_64",
                    "manylinux_2_28_x86_64",
                    "manylinux_2_34_x86_64",
                ),
            }
            for version in AMAZON_LINUX_2023_RUNTIMES
        }
    )

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        handler: str,
        runtime: str,
        version: int | Version | AutoVersion | None = None,
        min_version: int | None = None,
        alias: str | Alias | BlueGreenAliases | None = None,
        code_asset: PyFunctionAsset | None = None,
        code_dir: str | None = None,
        requirement_file: str | None = None,
        code_version: int | None = None,
        timeout: int = 3,
        memory_size: int | None = None,
        ephemeral_storage_size: int | None = None,
        logs_retention_in_days: int | None = 731,
        reserved_concurrent_executions: int | None = None,
        environment: dict[str, str] | None = None,
        logging_config: awslambda.LoggingConfig | None = None,
        dl_config: awslambda.DeadLetterConfig | None = None,
        vpc_config: awslambda.VPCConfig | None = None,
    ):
        """Initialize an AWS lambda function with a Python runtime.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param handler: name of the function to be invoked on lambda execution
        :param runtime: lambda runtime. It must be a Python runtime.
        :param version: the latest deployed version
        :param min_version: minimum deployed version (default 1)
        :param alias: alias for the latest version
        :param code_asset: asset containing the python code
        :param code_dir: directory containing the python code
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
        :param logging_config: The function's Amazon CloudWatch Logs settings
        :param dl_config: The dead letter config that specifies the topic or queue where
            lambda sends asynchronous events when they fail processing
        :param vpc_config: For network connectivity to AWS resources in a VPC, specify
            a list of security groups and subnets in the VPC. When you connect a
            function to a VPC, it can access resources and the internet only
            through that VPC
        """
        assert runtime.startswith("python"), "PyFunction only accept Python runtimes"
        super().__init__(
            name=name,
            description=description,
            code_bucket=None,
            code_key=None,
            role=role,
            version=version,
            min_version=min_version,
            alias=alias,
            handler=handler,
            code_version=code_version,
            timeout=timeout,
            runtime=runtime,
            memory_size=memory_size,
            ephemeral_storage_size=ephemeral_storage_size,
            logs_retention_in_days=logs_retention_in_days,
            reserved_concurrent_executions=reserved_concurrent_executions,
            environment=environment,
            logging_config=logging_config,
            dl_config=dl_config,
            vpc_config=vpc_config,
        )
        self.code_dir = code_dir
        self.requirement_file = requirement_file

        if code_asset is not None:
            self.code_asset = code_asset
        else:
            assert (
                code_dir is not None
            ), "code_dir must be provided when code_asset is None"

            self.code_asset = PyFunctionAsset(
                name=name_to_id(f"{name}Sources"),
                code_dir=code_dir,
                runtime=runtime,
                requirement_file=requirement_file,
            )

    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
        """Compute AWS resources for the construct."""
        assert isinstance(stack.s3_bucket, str)
        return [self.code_asset] + self.lambda_resources(
            code_bucket=stack.s3_bucket,
            code_key=Sub(
                f"{stack.s3_assets_key}${{{self.code_asset.s3_key_parameter_name}}}"
            ),
        )

    @client("lambda")
    def _exist_version(
        self, version: Version, client: botocore.client.BaseClient
    ) -> bool:
        """Check if a version of the function exists.

        The check works by listing all the versions and checking the descriptions
        as there is no way to get the number of a version by its logical id.

        :param version: the version
        :param client: an AWS client
        :return: if it exists
        """
        paginator = client.get_paginator("list_versions_by_function")
        for results in paginator.paginate(FunctionName=self.name):
            for item in results["Versions"]:
                if item["Description"] == version.description:
                    return True

        return False

    @client("lambda")
    def download_code_asset(
        self,
        dest: str,
        client: botocore.client.BaseClient,
        filename: str | None = None,
        qualifier: str | None = None,
    ) -> None:
        """Download the code asset of this function.

        :param dest: destination directory
        :param client: an AWS client
        :param filename: destination file
        :param qualifier: an alias or version of the function
        """
        params: dict[str, Any] = {}
        if qualifier is not None:
            params["Qualifier"] = qualifier

        resp = client.get_function(FunctionName=self.name, **params)

        HTTPSession().download_file(
            url=resp["Code"]["Location"], dest=dest, filename=filename
        )

    def _show_archive_files(self, archive_path: str) -> list[str]:
        """Output the newline separated list of files of an archive.

        The .pyc files are omitted to reduce the size of the output.

        :param archive_path: path to the archive
        :return: the list of files in the archive
        """
        with zipfile.ZipFile(archive_path) as zip:
            return [
                f"{line}\n"
                for line in sorted(zip.namelist())
                if not line.endswith(".pyc")
            ]

    def diff(self, stack: Stack, qualifier: str | None = None) -> None:
        """Compare this function with the currently deployed one.

        :param stack: the stack that contains the function
        :param qualifier: an alias or version to compare with
        """
        if qualifier is None:
            # In case of blue/green aliases, perform the diff on both aliases
            if isinstance(self.alias, BlueGreenAliases):
                for alias in [self.alias.blue, self.alias.green]:
                    self.diff(stack=stack, qualifier=alias.alias_name)
                return

            # Perform the diff on the alias if set
            if self.alias is not None:
                qualifier = self.alias.alias_name

        name_with_qualifier = "{}{}".format(
            self.name, f":{qualifier}" if qualifier is not None else ""
        )

        # If the function is versioned, then check if the latest version
        # is already deployed
        if self.version is not None:
            version = (
                self.version
                if isinstance(self.version, Version)
                else self.version.latest
            )

            try:
                # If the version already exists then we are not deploying anything
                # as a version is immutable. So there are no changes in that case
                if self._exist_version(version=version):
                    print(f"No new version for function {name_with_qualifier}")
                    return
            except botocore.exceptions.ClientError as e:
                # We can get a genuine AccessDeniedException depending on conditions
                # in the policy if the lambda doesn't exist yet. In such cases it's
                # better to not fail
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    logger.exception(f"Failed to fetch function {self.name} versions:")

        # Otherwise we are redeploying the function, so we get the list of files
        # from the local code asset
        archive_files = self._show_archive_files(self.code_asset.archive_path)

        # Download the code archive of the deployed function by pointing either
        # at the alias or at None ($LATEST)
        active_archive_files: list[str] = []
        try:
            with TemporaryDirectory() as tmpd:
                archive_name = "archive.zip"
                self.download_code_asset(
                    dest=tmpd,
                    filename=archive_name,
                    qualifier=qualifier,
                )

                # Output lines of the code archive
                active_archive_files = self._show_archive_files(
                    os.path.join(tmpd, archive_name)
                )
        except botocore.exceptions.ClientError as e:
            # We can get a genuine AccessDeniedException depending on conditions
            # in the policy if the lambda doesn't exist yet. In such cases it's
            # better to not fail
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.exception(f"Failed to fetch function {self.name} code asset:")

        diff = modified_diff_lines(
            list(difflib.ndiff(active_archive_files, archive_files))
        )
        if diff:
            print(f"Diff for the new version of function {name_with_qualifier}:")
            print("".join(color_diff(diff)))
        else:
            print(f"No diff for the new version of function {name_with_qualifier}")

    def show(self, stack: Stack) -> None:
        files = self._show_archive_files(self.code_asset.archive_path)
        print(f"List of files for function {self.name}:")
        if files:
            print("".join(files))
        else:
            print("No files")


class Py38Function(PyFunction):
    """Lambda using the Python 3.8 runtime."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        code_dir: str,
        handler: str,
        version: int | Version | AutoVersion | None = None,
        min_version: int | None = None,
        alias: str | Alias | BlueGreenAliases | None = None,
        requirement_file: str | None = None,
        code_version: int | None = None,
        timeout: int = 3,
        memory_size: int | None = None,
        ephemeral_storage_size: int | None = None,
        logs_retention_in_days: int | None = None,
        reserved_concurrent_executions: int | None = None,
        logging_config: awslambda.LoggingConfig | None = None,
        dl_config: awslambda.DeadLetterConfig | None = None,
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
            version=version,
            min_version=min_version,
            alias=alias,
            requirement_file=requirement_file,
            code_version=code_version,
            timeout=timeout,
            runtime="python3.8",
            memory_size=memory_size,
            ephemeral_storage_size=ephemeral_storage_size,
            logs_retention_in_days=logs_retention_in_days,
            reserved_concurrent_executions=reserved_concurrent_executions,
            logging_config=logging_config,
            dl_config=dl_config,
        )


class Alias(Construct):
    """A lambda alias."""

    def __init__(
        self,
        name: str,
        lambda_version: str | GetAtt | Version,
        description: str | None = None,
        lambda_arn: str | GetAtt | Ref | None = None,
        alias_name: str | None = None,
        provisioned_concurrency_config: (
            awslambda.ProvisionedConcurrencyConfiguration | None
        ) = None,
        routing_config: awslambda.AliasRoutingConfiguration | None = None,
    ):
        """Initialize an AWS lambda alias.

        :param name: name of the resource
        :param lambda_version: the function version that the alias invokes
        :param description: a description of the alias
        :param lambda_arn: the name of the Lambda function
        :param alias_name: name of the alias. By default the parameter
            name will be used as both the name of the resource and the name
            of the alias, so this allows for a different alias name. For
            example if you have multiple Lambda functions using the same
            alias names
        :param provisioned_concurrency_config: specifies a provisioned
            concurrency configuration for a function's alias
        :param routing_config: the routing configuration of the alias
        """
        if lambda_arn is not None:
            logger.warning("lambda_arn is deprecated, do not use Alias as a Construct")
        self.name = name
        self.description = description
        self.alias_name = alias_name
        self.lambda_arn = lambda_arn
        self.lambda_version = lambda_version
        self.provisioned_concurrency_config = provisioned_concurrency_config
        self.routing_config = routing_config

    @property
    def ref(self) -> Ref:
        return Ref(name_to_id(self.name))

    @property
    def as_dict(self) -> dict:
        """Return dictionary representation of the lambda alias."""
        lambda_version = (
            self.lambda_version.version
            if isinstance(self.lambda_version, Version)
            else self.lambda_version
        )

        result: dict[str, Any] = {
            "Name": self.alias_name if self.alias_name is not None else self.name,
            "FunctionVersion": lambda_version,
        }

        if self.description is not None:
            result["Description"] = self.description

        if self.provisioned_concurrency_config is not None:
            result["ProvisionedConcurrencyConfig"] = self.provisioned_concurrency_config

        if self.routing_config is not None:
            result["RoutingConfig"] = self.routing_config

        return result

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        return [
            awslambda.Alias(
                name_to_id(self.name), **self.as_dict, FunctionName=self.lambda_arn
            )
        ]


class Version(Construct):
    """A lambda version."""

    def __init__(
        self,
        name: str,
        description: str | None = None,
        lambda_arn: str | GetAtt | Ref | None = None,
        provisioned_concurrency_config: (
            awslambda.ProvisionedConcurrencyConfiguration | None
        ) = None,
        code_sha256: str | None = None,
    ):
        """Initialize an AWS lambda version.

        :param name: version name
        :param description: a description for the version to override the description
            in the function configuration. Updates are not supported for this property
        :param lambda_arn: the name of the Lambda function (deprecated)
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

    @property
    def as_dict(self) -> dict:
        """Return dictionary representation of the lambda version."""
        result: dict[str, Any] = {}

        if self.description is not None:
            result["Description"] = self.description

        if self.provisioned_concurrency_config is not None:
            result["ProvisionedConcurrencyConfig"] = self.provisioned_concurrency_config

        if self.code_sha256 is not None:
            result["CodeSha256"] = self.code_sha256

        return result

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        return [
            awslambda.Version(
                name_to_id(self.name), **self.as_dict, FunctionName=self.lambda_arn
            )
        ]


class AutoVersion(Construct):
    """Automatic lambda versions."""

    def __init__(
        self,
        version: int,
        min_version: int | None = None,
        lambda_name: str | None = None,
        lambda_arn: str | GetAtt | Ref | None = None,
        lambda_function: Function | None = None,
        provisioned_concurrency_config: (
            awslambda.ProvisionedConcurrencyConfiguration | None
        ) = None,
        code_sha256: str | None = None,
    ) -> None:
        """Create lambda versions from 1 to version included.

        When using this construct, you must provide either a lambda function or
        a lambda name plus arn.

        Parameters provisioned_concurrency_config and code_sha256 are only relevant
        for when creating a new version.

        :param version: number of the latest version
        :param min_version: minimum deployed version (default 1)
        :param lambda_name: the name of the Lambda function (used as a prefix for
            the name of each versions, and in the descriptions)
        :param lambda_arn: the arn of the Lambda function (deprecated)
        :param lambda_function: the Lambda function (deprecated)
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
        if lambda_function is not None:
            logger.warning("lambda_function is deprecated, use lambda_name instead")
        if lambda_arn is not None:
            logger.warning("lambda_arn is deprecated, use lambda_name instead")
        self.version = version
        self.min_version = min_version if min_version is not None else 1
        self.lambda_function = lambda_function
        self.lambda_name = lambda_function.name if lambda_function else lambda_name
        self.lambda_arn = lambda_function.arn if lambda_function else lambda_arn
        self.versions = [
            Version(
                name=f"{self.lambda_name}Version{i}",
                description=f"version {i} of {self.lambda_name} lambda",
                lambda_arn=self.lambda_arn,
            )
            for i in range(self.min_version, version + 1)
        ]
        self.latest.provisioned_concurrency_config = provisioned_concurrency_config
        self.latest.code_sha256 = code_sha256

    def get_version(self, number: int) -> Version:
        """Return a version.

        :param number: version number
        :raises ValueError: if number is out of range
        """
        index = number - self.min_version

        if index >= 0 and index < len(self.versions):
            return self.versions[index]

        raise ValueError(f"version {number} if out of range")

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


class BlueGreenVersions(AutoVersion):
    """Automatic blue/green lambda versions."""

    def __init__(
        self,
        blue_version: int,
        green_version: int,
        min_version: int | None = None,
        lambda_name: str | None = None,
        lambda_arn: str | GetAtt | Ref | None = None,
        lambda_function: Function | None = None,
        provisioned_concurrency_config: (
            awslambda.ProvisionedConcurrencyConfiguration | None
        ) = None,
        code_sha256: str | None = None,
    ) -> None:
        """Create lambda versions from min_version to blue/green versions included.

        See AutoVersion.

        :param blue_version: number of the blue version
        :param green_version: number of the green version
        :param min_version: minimum deployed version (default 1)
        :param lambda_name: the name of the Lambda function (used as a prefix for
            the name of each versions, and in the descriptions)
        :param lambda_arn: the arn of the Lambda function (deprecated)
        :param lambda_function: the Lambda function (deprecated)
        :param provisioned_concurrency_config: specifies a provisioned concurrency
            configuration for a function's version. Updates are not supported for this
            property.
        :param code_sha256: only publish a version if the hash value matches the value
            that's specified. Use this option to avoid publishing a version if the
            function code has changed since you last updated it. Updates are not
            supported for this property
        """
        super().__init__(
            version=max(blue_version, green_version),
            min_version=min_version,
            lambda_name=lambda_name,
            lambda_arn=lambda_arn,
            lambda_function=lambda_function,
            provisioned_concurrency_config=provisioned_concurrency_config,
            code_sha256=code_sha256,
        )
        self.blue_version = blue_version
        self.green_version = green_version

    @property
    def blue(self) -> Version:
        """Return the blue version."""
        return self.get_version(self.blue_version)

    @property
    def green(self) -> Version:
        """Return the green version."""
        return self.get_version(self.green_version)


class BlueGreenAliasConfiguration(object):
    """Blue/Green alias configuration."""

    def __init__(
        self,
        version: str | GetAtt | Version,
        name: str | None = None,
        provisioned_concurrency_config: (
            awslambda.ProvisionedConcurrencyConfiguration | None
        ) = None,
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
        :param lambda_name: the name of the Lambda function (used as a prefix
            in the name of each aliases, and in the descriptions)
        :param lambda_arn: the arn of the Lambda function (deprecated)
        :param lambda_function: the Lambda function (deprecated)
        """
        if lambda_function is not None:
            logger.warning("lambda_function is deprecated, use lambda_name instead")
        if lambda_arn is not None:
            logger.warning("lambda_arn is deprecated, use lambda_name instead")
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
            id = name_to_id(f"{self.lambda_name}-{name}-alias")
            return Alias(
                name=id,
                description=f"{name} alias for {self.lambda_name} lambda",
                alias_name=config.name if config.name is not None else id,
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
