from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from troposphere import awslambda, GetAtt, Ref

from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from e3.sys import python_script
from e3.os.process import Run
from e3.fs import sync_tree, rm
from e3.archive import create_archive
import os

if TYPE_CHECKING:
    from typing import Optional, Union
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack


class Function(Construct):
    """A lambda function."""

    def __init__(
        self,
        name: str,
        description: str,
        code_bucket: Optional[str],
        code_key: Optional[str],
        role: Union[str, GetAtt],
        handler: Optional[str] = None,
        code_version: Optional[int] = None,
        timeout: int = 3,
        runtime: Optional[str] = None,
        memory_size: Optional[int] = None,
    ):
        """Initialize an AWS lambda function.

        :param name: function name
        :param description: a description of the function
        :param code_bucket: bucket in which code for the function is found
        :param code_key: key in the previous bucket where the code is stored
        :param role: role to be asssumed during lambda execution
        :param handler: handler name (i.e: entry point)
        :param code_version: code version
        :param timeout: maximum execution time (default: 3s)
        :param runtime: runtime to use
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        """
        self.name = name
        self.description = description
        self.code_bucket = code_bucket
        self.code_key = code_key
        self.code_version = code_version
        self.timeout = timeout
        self.runtime = runtime
        self.role = role
        self.handler = handler
        self.memory_size = memory_size

    def cfn_policy_document(self, stack: Stack) -> PolicyDocument:
        return PolicyDocument(
            [
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
                ),
                # Allow user to pass role to the lambda
                PolicyStatement(
                    action=["iam:PassRole"], effect="Allow", resource=self.role
                ),
            ]
        )

    @property
    def arn(self) -> GetAtt:
        """Arn of the lambda funtion."""
        return GetAtt(name_to_id(self.name), "Arn")

    @property
    def ref(self) -> Ref:
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        assert isinstance(self.code_bucket, str)
        assert isinstance(self.code_key, str)
        return self.lambda_resources(
            code_bucket=self.code_bucket, code_key=self.code_key
        )

    def lambda_resources(self, code_bucket: str, code_key: str) -> list[AWSObject]:
        """Return resource associated with the construct.

        :param code_bucket: bucket in which the lambda code is located
        :param code_key: location of the code in the bucket
        """
        code_params = {"S3Bucket": code_bucket, "S3Key": code_key}
        if self.code_version is not None:
            code_params["S3ObjectVersion"] = str(self.code_version)

        params = {
            "Code": awslambda.Code(**code_params),
            "Timeout": self.timeout,
            "Description": self.description,
            "Role": self.role,
            "FunctionName": self.name,
        }

        if self.runtime is not None:
            params["Runtime"] = self.runtime

        if self.handler is not None:
            params["Handler"] = self.handler

        if self.memory_size is not None:
            params["MemorySize"] = self.memory_size

        return [awslambda.Function(name_to_id(self.name), **params)]

    def invoke_permission(
        self,
        name_suffix: str,
        service: str,
        source_arn: str,
        source_account: Optional[str],
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


class Py38Function(Function):
    """Lambda using the Python 3.8 runtime."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt,
        code_dir: str,
        handler: str,
        requirement_file: Optional[str] = None,
        code_version: Optional[int] = None,
        timeout: int = 3,
        memory_size: Optional[int] = None,
    ):
        """Initialize an AWS lambda function using Python 3.8 runtime.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param code_dir: directory containing the python code
        :param handler: name of the function to be invoked on lambda execution
        :param requirement_file: requirement file for the application code.
            Required packages are automatically fetched (works only from linux)
            and packaged along with the lambda code
        :param code_version: code version
        :param timeout: maximum execution time (default: 3s)
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        """
        super().__init__(
            name=name,
            description=description,
            code_bucket=None,
            code_key=None,
            role=role,
            handler=handler,
            code_version=code_version,
            timeout=timeout,
            runtime="python3.8",
            memory_size=memory_size,
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

        # Add lambda code
        sync_tree(self.code_dir, package_dir, delete=False)

        # Create an archive
        create_archive(
            f"{self.name}_lambda.zip",
            from_dir=package_dir,
            dest=root_dir,
            no_root_dir=True,
        )

        # Remove temporary directory
        rm(package_dir, recursive=True)
