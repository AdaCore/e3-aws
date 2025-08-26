from __future__ import annotations
from typing import TYPE_CHECKING
import base64
import docker
import os
import pytest
import json
import io
from unittest.mock import patch
import sys

from flask import Flask, send_file
from troposphere.awslambda import (
    ProvisionedConcurrencyConfiguration,
    AliasRoutingConfiguration,
    VersionWeight,
    LoggingConfig,
    DeadLetterConfig,
    VPCConfig,
)

from e3.aws import AWSEnv
from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import (
    Function,
    PyFunction,
    Py38Function,
    DockerFunction,
    Alias,
    Version,
    AutoVersion,
    BlueGreenVersions,
    BlueGreenAliases,
    BlueGreenAliasConfiguration,
)
from e3.aws.troposphere.awslambda.flask_apigateway_wrapper import FlaskLambdaHandler

from e3.pytest import require_tool

from e3.aws.troposphere.sqs import Queue

if TYPE_CHECKING:
    from typing import Iterable, Callable
    from flask import Response
    from pathlib import Path


SOURCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "source_dir")


has_docker = require_tool("docker")


EXPECTED_PY38FUNCTION_TEMPLATE = {
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": "templates/mypylambda_lambda.zip",
            },
            "Description": "this is a test",
            "FunctionName": "mypylambda",
            "Handler": "app.main",
            "Role": "somearn",
            "Runtime": "python3.8",
            "Timeout": 3,
        },
        "Type": "AWS::Lambda::Function",
    }
}

EXPECTED_PYFUNCTION_DEFAULT_TEMPLATE = {
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": "templates/mypylambda_lambda.zip",
            },
            "Description": "this is a test",
            "FunctionName": "mypylambda",
            "Handler": "app.main",
            "Role": "somearn",
            "Runtime": "python3.9",
            "Timeout": 3,
            "EphemeralStorage": {"Size": 4096},
            "Environment": {
                "Variables": {"env_key_1": "env_value_1", "env_key_2": "env_value2"}
            },
        },
        "Type": "AWS::Lambda::Function",
    },
    "MypylambdaLogGroup": {
        "DeletionPolicy": "Retain",
        "Properties": {
            "LogGroupName": "/aws/lambda/mypylambda",
            "RetentionInDays": 731,
        },
        "Type": "AWS::Logs::LogGroup",
    },
}

EXPECTED_PYFUNCTION_TEMPLATE = {
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": "templates/mypylambda_lambda.zip",
            },
            "Description": "this is a test",
            "FunctionName": "mypylambda",
            "Handler": "app.main",
            "Role": "somearn",
            "Runtime": "python3.9",
            "Timeout": 3,
            "MemorySize": 128,
            "EphemeralStorage": {"Size": 1024},
            "ReservedConcurrentExecutions": 1,
            "Environment": {
                "Variables": {"env_key_1": "env_value_1", "env_key_2": "env_value2"}
            },
            "LoggingConfig": {
                "ApplicationLogLevel": "INFO",
                "LogFormat": "JSON",
                "SystemLogLevel": "WARN",
            },
        },
        "Type": "AWS::Lambda::Function",
    },
    "MypylambdaLogGroup": {
        "DeletionPolicy": "Retain",
        "Properties": {
            "LogGroupName": "/aws/lambda/mypylambda",
            "RetentionInDays": 7,
        },
        "Type": "AWS::Logs::LogGroup",
    },
}

EXPECTED_PYFUNCTION_WITH_DLQ_TEMPLATE = {
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": "templates/mypylambda_lambda.zip",
            },
            "DeadLetterConfig": {
                "TargetArn": {"Fn::GetAtt": ["PyFunctionDLQ", "Arn"]},
            },
            "Description": "this is a test with dlconfig",
            "FunctionName": "mypylambda",
            "Handler": "app.main",
            "Role": "somearn",
            "Runtime": "python3.12",
            "Timeout": 3,
            "MemorySize": 128,
            "EphemeralStorage": {"Size": 1024},
            "ReservedConcurrentExecutions": 1,
            "Environment": {
                "Variables": {"env_key_1": "env_value_1", "env_key_2": "env_value2"}
            },
            "LoggingConfig": {
                "ApplicationLogLevel": "INFO",
                "LogFormat": "JSON",
                "SystemLogLevel": "WARN",
            },
        },
        "Type": "AWS::Lambda::Function",
    },
    "MypylambdaLogGroup": {
        "DeletionPolicy": "Retain",
        "Properties": {
            "LogGroupName": "/aws/lambda/mypylambda",
            "RetentionInDays": 7,
        },
        "Type": "AWS::Logs::LogGroup",
    },
    "PyFunctionDLQ": {
        "Properties": {
            "QueueName": "PyFunctionDLQ",
            "VisibilityTimeout": 30,
        },
        "Type": "AWS::SQS::Queue",
    },
}

EXPECTED_PYFUNCTION_WITH_VPC_TEMPLATE = {
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": "templates/mypylambda_lambda.zip",
            },
            "Description": "this is a test with vpcconfig",
            "FunctionName": "mypylambda",
            "Handler": "app.main",
            "Role": "somearn",
            "Runtime": "python3.12",
            "Timeout": 3,
            "VpcConfig": {
                "SecurityGroupIds": [
                    "sg-085912345678492fb",
                ],
                "SubnetIds": [
                    "subnet-071f712345678e7c8",
                    "subnet-07fd123456788a036",
                ],
            },
            "MemorySize": 128,
            "EphemeralStorage": {"Size": 1024},
            "ReservedConcurrentExecutions": 1,
            "Environment": {
                "Variables": {"env_key_1": "env_value_1", "env_key_2": "env_value2"}
            },
            "LoggingConfig": {
                "ApplicationLogLevel": "INFO",
                "LogFormat": "JSON",
                "SystemLogLevel": "WARN",
            },
        },
        "Type": "AWS::Lambda::Function",
    },
    "MypylambdaLogGroup": {
        "DeletionPolicy": "Retain",
        "Properties": {
            "LogGroupName": "/aws/lambda/mypylambda",
            "RetentionInDays": 7,
        },
        "Type": "AWS::Logs::LogGroup",
    },
}

EXPECTED_PYFUNCTION_POLICY_DOCUMENT = {
    "Statement": [
        {
            "Action": [
                "lambda:CreateFunction",
                "lambda:GetFunction",
                "lambda:DeleteFunction",
                "lambda:UpdateFunctionCode",
                "lambda:UpdateFunctionConfiguration",
                "lambda:GetFunctionConfiguration",
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:lambda:::function:mypylambda*",
        },
        {"Action": ["iam:PassRole"], "Effect": "Allow", "Resource": "somearn"},
    ],
    "Version": "2012-10-17",
}

EXPECTED_DOCKER_FUNCTION = {
    "Dockerfunction": {
        "Properties": {
            "PackageType": "Image",
            "Code": {"ImageUri": "<dry_run_image_uri>"},
            "Timeout": 3,
            "Description": "this is a test",
            "Role": "somearn",
            "FunctionName": "dockerfunction",
        },
        "Type": "AWS::Lambda::Function",
    },
    "DockerfunctionLogGroup": {
        "DeletionPolicy": "Retain",
        "Properties": {
            "LogGroupName": "/aws/lambda/dockerfunction",
            "RetentionInDays": 731,
        },
        "Type": "AWS::Logs::LogGroup",
    },
}

EXPECTED_VERSION_DEFAULT_TEMPLATE = {
    "Prod": {
        "Properties": {
            "Description": "this is the prod version",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    }
}

EXPECTED_VERSION_TEMPLATE = {
    "Prod": {
        "Properties": {
            "Description": "this is the prod version",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": 1},
            "CodeSha256": "somesha",
        },
        "Type": "AWS::Lambda::Version",
    }
}

EXPECTED_ALIAS_DEFAULT_TEMPLATE = {
    "Myalias": {
        "Properties": {
            "Name": "myalias",
            "Description": "this is a test",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": "1",
        },
        "Type": "AWS::Lambda::Alias",
    }
}

EXPECTED_ALIAS_TEMPLATE = {
    "Myalias": {
        "Properties": {
            "Name": "myalias",
            "Description": "this is a test",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Fn::GetAtt": ["Newversion", "Version"]},
            "ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": 1},
            "RoutingConfig": {
                "AdditionalVersionWeights": [
                    {
                        "FunctionVersion": {"Fn::GetAtt": ["Oldversion", "Version"]},
                        "FunctionWeight": 0.5,
                    }
                ]
            },
        },
        "Type": "AWS::Lambda::Alias",
    }
}

EXPECTED_AUTOVERSION_DEFAULT_TEMPLATE = {
    "MypylambdaVersion1": {
        "Properties": {
            "Description": "version 1 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    },
    "MypylambdaVersion2": {
        "Properties": {
            "Description": "version 2 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    },
}

EXPECTED_AUTOVERSION_SINGLE_TEMPLATE = {
    "MypylambdaVersion1": {
        "Properties": {
            "Description": "version 1 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    }
}

EXPECTED_AUTOVERSION_TEMPLATE = {
    "MypylambdaVersion2": {
        "Properties": {
            "Description": "version 2 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    },
    "MypylambdaVersion3": {
        "Properties": {
            "Description": "version 3 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": 1},
            "CodeSha256": "somesha",
        },
        "Type": "AWS::Lambda::Version",
    },
}

EXPECTED_BLUEGREENVERSIONS_TEMPLATE = {
    "MypylambdaVersion1": {
        "Properties": {
            "Description": "version 1 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    },
    "MypylambdaVersion2": {
        "Properties": {
            "Description": "version 2 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    },
    "MypylambdaVersion3": {
        "Properties": {
            "Description": "version 3 of mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
        },
        "Type": "AWS::Lambda::Version",
    },
}

EXPECTED_BLUEGREENALIASES_DEFAULT_TEMPLATE = {
    "MypylambdaBlueAlias": {
        "Properties": {
            "Name": "MypylambdaBlueAlias",
            "Description": "blue alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Fn::GetAtt": ["MypylambdaVersion1", "Version"]},
        },
        "Type": "AWS::Lambda::Alias",
    },
    "MypylambdaGreenAlias": {
        "Properties": {
            "Name": "MypylambdaGreenAlias",
            "Description": "green alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Fn::GetAtt": ["MypylambdaVersion2", "Version"]},
        },
        "Type": "AWS::Lambda::Alias",
    },
}

EXPECTED_BLUEGREENALIASES_TEMPLATE = {
    "MypylambdaProdAlias": {
        "Properties": {
            "Name": "prod",
            "Description": "prod alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Fn::GetAtt": ["MypylambdaVersion1", "Version"]},
            "ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": 1},
            "RoutingConfig": {
                "AdditionalVersionWeights": [
                    {
                        "FunctionVersion": {
                            "Fn::GetAtt": ["MypylambdaVersion1", "Version"]
                        },
                        "FunctionWeight": 1,
                    }
                ]
            },
        },
        "Type": "AWS::Lambda::Alias",
    },
    "MypylambdaBetaAlias": {
        "Properties": {
            "Name": "beta",
            "Description": "beta alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Fn::GetAtt": ["MypylambdaVersion2", "Version"]},
            "ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": 1},
            "RoutingConfig": {
                "AdditionalVersionWeights": [
                    {
                        "FunctionVersion": {
                            "Fn::GetAtt": ["MypylambdaVersion2", "Version"]
                        },
                        "FunctionWeight": 1,
                    }
                ]
            },
        },
        "Type": "AWS::Lambda::Alias",
    },
}


@pytest.fixture
def simple_lambda_function() -> PyFunction:
    """Return a simple lambda function for testing."""
    return PyFunction(
        name="mypylambda",
        description="this is a test",
        role="somearn",
        runtime="python3.9",
        code_dir="my_code_dir",
        handler="app.main",
    )


def test_py38function(stack: Stack) -> None:
    """Test Py38Function creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        Py38Function(
            name="mypylambda",
            description="this is a test",
            role="somearn",
            code_dir="my_code_dir",
            handler="app.main",
        )
    )
    assert stack.export()["Resources"] == EXPECTED_PY38FUNCTION_TEMPLATE


def test_pyfunction_default(stack: Stack) -> None:
    """Test PyFunction creation with default settings."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        PyFunction(
            name="mypylambda",
            description="this is a test",
            role="somearn",
            runtime="python3.9",
            code_dir="my_code_dir",
            handler="app.main",
            ephemeral_storage_size=4096,
            environment={"env_key_1": "env_value_1", "env_key_2": "env_value2"},
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_PYFUNCTION_DEFAULT_TEMPLATE


def test_pyfunction(stack: Stack) -> None:
    """Test PyFunction creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        PyFunction(
            name="mypylambda",
            description="this is a test",
            role="somearn",
            runtime="python3.9",
            code_dir="my_code_dir",
            handler="app.main",
            memory_size=128,
            ephemeral_storage_size=1024,
            logs_retention_in_days=7,
            reserved_concurrent_executions=1,
            environment={"env_key_1": "env_value_1", "env_key_2": "env_value2"},
            logging_config=LoggingConfig(
                ApplicationLogLevel="INFO",
                LogFormat="JSON",
                SystemLogLevel="WARN",
            ),
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_PYFUNCTION_TEMPLATE


def test_pyfunction_with_dlconfig(stack: Stack) -> None:
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    dlq = Queue(name="PyFunctionDLQ")
    stack.add(dlq)
    stack.add(
        PyFunction(
            name="mypylambda",
            description="this is a test with dlconfig",
            role="somearn",
            runtime="python3.12",
            code_dir="my_code_dir",
            handler="app.main",
            memory_size=128,
            ephemeral_storage_size=1024,
            logs_retention_in_days=7,
            reserved_concurrent_executions=1,
            environment={"env_key_1": "env_value_1", "env_key_2": "env_value2"},
            logging_config=LoggingConfig(
                ApplicationLogLevel="INFO",
                LogFormat="JSON",
                SystemLogLevel="WARN",
            ),
            dl_config=DeadLetterConfig(TargetArn=dlq.arn),
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_PYFUNCTION_WITH_DLQ_TEMPLATE


def test_pyfunction_with_vpcconfig(stack: Stack) -> None:
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        PyFunction(
            name="mypylambda",
            description="this is a test with vpcconfig",
            role="somearn",
            runtime="python3.12",
            code_dir="my_code_dir",
            handler="app.main",
            memory_size=128,
            ephemeral_storage_size=1024,
            logs_retention_in_days=7,
            reserved_concurrent_executions=1,
            environment={"env_key_1": "env_value_1", "env_key_2": "env_value2"},
            logging_config=LoggingConfig(
                ApplicationLogLevel="INFO",
                LogFormat="JSON",
                SystemLogLevel="WARN",
            ),
            vpc_config=VPCConfig(
                "mypylambdavpc",
                SecurityGroupIds=["sg-085912345678492fb"],
                SubnetIds=["subnet-071f712345678e7c8", "subnet-07fd123456788a036"],
            ),
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_PYFUNCTION_WITH_VPC_TEMPLATE


@pytest.mark.parametrize(
    "python_version, platform_list",
    [
        ("3.9", ["manylinux_2_17_x86_64", "manylinux_2_24_x86_64"]),
        ("3.10", ["manylinux_2_17_x86_64", "manylinux_2_24_x86_64"]),
        ("3.11", ["manylinux_2_17_x86_64", "manylinux_2_24_x86_64"]),
        (
            "3.12",
            [
                "manylinux_2_17_x86_64",
                "manylinux_2_24_x86_64",
                "manylinux_2_28_x86_64",
                "manylinux_2_34_x86_64",
            ],
        ),
        (
            "3.13",
            [
                "manylinux_2_17_x86_64",
                "manylinux_2_24_x86_64",
                "manylinux_2_28_x86_64",
                "manylinux_2_34_x86_64",
            ],
        ),
    ],
)
def test_pyfunction_with_requirements(
    python_version: str, platform_list: list[str], tmp_path: Path, stack: Stack
) -> None:
    """Test PyFunction creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    code_dir = tmp_path

    with patch("e3.aws.troposphere.awslambda.Run") as mock_run:
        mock_run.return_value.status = 0
        PyFunction(
            name="mypylambda",
            description="this is a test",
            role="somearn",
            runtime=f"python{python_version}",
            code_dir=str(code_dir),
            handler="app.main",
            requirement_file="requirements.txt",
        ).create_data_dir("dummy")
    # Ensure the right pip command is called
    mock_run.assert_called_once_with(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            f"--python-version={python_version}",
            *(f"--platform={platform}" for platform in platform_list),
            "--implementation=cp",
            "--only-binary=:all:",
            "--target=dummy/Mypylambda/package",
            "-r",
            "requirements.txt",
        ],
        output=None,
    )


def test_pyfunction_policy_document(stack: Stack) -> None:
    """Test cfn_policy_document of PyFunction."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        PyFunction(
            name="mypylambda",
            description="this is a test",
            role="somearn",
            runtime="python3.9",
            code_dir="my_code_dir",
            handler="app.main",
        )
    )
    print(stack.cfn_policy_document().as_dict)
    assert stack.cfn_policy_document().as_dict == EXPECTED_PYFUNCTION_POLICY_DOCUMENT


@pytest.mark.skip(
    reason="This test does not work in GitLab CI jobs. Disable it for now.",
)
def test_docker_function(stack: Stack, has_docker: Callable) -> None:
    """Test adding docker function to stack."""
    aws_env = AWSEnv(regions=["us-east-1"], stub=True)
    stubber_ecr = aws_env.stub("ecr")

    stubber_ecr.add_response(
        "get_authorization_token",
        {
            "authorizationData": [
                {
                    "authorizationToken": base64.b64encode(
                        b"test_user:test_pwd"
                    ).decode(),
                    "proxyEndpoint": "test_endpoint",
                }
            ]
        },
        {},
    )

    stack.deploy_session = aws_env
    docker_function = DockerFunction(
        name="dockerfunction",
        description="this is a test",
        role="somearn",
        source_dir=SOURCE_DIR,
        repository_name="e3_aws_test_repository",
        image_tag="test_tag",
    )
    client = docker.from_env()
    try:
        stack.add(docker_function)
    except docker.errors.APIError:
        # Push is expected to fail
        pass
    finally:
        # Always try to remove local test image
        client.images.remove(f"e3_aws_test_repository:{docker_function.image_tag}")

    # Add resources without trying to push the image to ECR
    stack.dry_run = True
    stack.add(docker_function)

    assert stack.export()["Resources"] == EXPECTED_DOCKER_FUNCTION


def test_version_default(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test Version creation with default settings."""
    stack.add(
        Version(
            name="prod",
            description="this is the prod version",
            lambda_arn=simple_lambda_function.arn,
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_VERSION_DEFAULT_TEMPLATE


def test_version(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test Version creation."""
    stack.add(
        Version(
            name="prod",
            description="this is the prod version",
            lambda_arn=simple_lambda_function.arn,
            provisioned_concurrency_config=ProvisionedConcurrencyConfiguration(
                ProvisionedConcurrentExecutions=1
            ),
            code_sha256="somesha",
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_VERSION_TEMPLATE


def test_alias_default(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test Alias creation with default settings."""
    stack.add(
        Alias(
            name="myalias",
            description="this is a test",
            lambda_arn=simple_lambda_function.arn,
            lambda_version="1",
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_ALIAS_DEFAULT_TEMPLATE


def test_alias(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test Alias creation."""
    new_version = Version(
        name="newversion",
        description="this is the new version",
        lambda_arn=simple_lambda_function.arn,
    )

    old_version = Version(
        name="oldversion",
        description="this is the old version",
        lambda_arn=simple_lambda_function.arn,
    )

    stack.add(
        Alias(
            name="myalias",
            description="this is a test",
            lambda_arn=simple_lambda_function.arn,
            lambda_version=new_version.version,
            provisioned_concurrency_config=ProvisionedConcurrencyConfiguration(
                ProvisionedConcurrentExecutions=1
            ),
            routing_config=AliasRoutingConfiguration(
                AdditionalVersionWeights=[
                    VersionWeight(
                        FunctionVersion=old_version.version, FunctionWeight=0.5
                    )
                ]
            ),
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_ALIAS_TEMPLATE


def test_autoversion_default(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test AutoVersion creation with default settings."""
    auto_version = AutoVersion(
        2,
        lambda_function=simple_lambda_function,
    )
    stack.add(auto_version)
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_AUTOVERSION_DEFAULT_TEMPLATE
    assert auto_version.get_version(1).name == "mypylambdaVersion1"
    assert auto_version.get_version(2).name == "mypylambdaVersion2"
    assert auto_version.previous.name == "mypylambdaVersion1"
    assert auto_version.latest.name == "mypylambdaVersion2"

    with pytest.raises(ValueError):
        auto_version.get_version(3)


def test_autoversion_single(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test AutoVersion creation with a single version."""
    auto_version = AutoVersion(
        1,
        lambda_function=simple_lambda_function,
    )
    stack.add(auto_version)
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_AUTOVERSION_SINGLE_TEMPLATE
    assert auto_version.previous.name == "mypylambdaVersion1"
    assert auto_version.latest.name == "mypylambdaVersion1"


def test_autoversion(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test AutoVersion creation."""
    auto_version = AutoVersion(
        3,
        min_version=2,
        lambda_name=simple_lambda_function.name,
        lambda_arn=simple_lambda_function.arn,
        provisioned_concurrency_config=ProvisionedConcurrencyConfiguration(
            ProvisionedConcurrentExecutions=1
        ),
        code_sha256="somesha",
    )
    stack.add(auto_version)
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_AUTOVERSION_TEMPLATE
    assert auto_version.get_version(2).name == "mypylambdaVersion2"
    assert auto_version.get_version(3).name == "mypylambdaVersion3"
    assert auto_version.previous.name == "mypylambdaVersion2"
    assert auto_version.latest.name == "mypylambdaVersion3"


def test_bluegreenversions(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test BlueGreenVersions creation."""
    versions = BlueGreenVersions(
        blue_version=2,
        green_version=3,
        lambda_function=simple_lambda_function,
    )
    stack.add(versions)
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_BLUEGREENVERSIONS_TEMPLATE
    assert versions.blue.name == "mypylambdaVersion2"
    assert versions.green.name == "mypylambdaVersion3"


def test_bluegreenaliases_default(
    stack: Stack, simple_lambda_function: PyFunction
) -> None:
    """Test BlueGreenAliases creation with default settings."""
    auto_version = AutoVersion(
        2,
        lambda_function=simple_lambda_function,
    )
    aliases = BlueGreenAliases(
        blue_config=BlueGreenAliasConfiguration(version=auto_version.previous),
        green_config=BlueGreenAliasConfiguration(version=auto_version.latest),
        lambda_function=simple_lambda_function,
    )
    stack.add(aliases)
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_BLUEGREENALIASES_DEFAULT_TEMPLATE
    assert aliases.blue.name == "MypylambdaBlueAlias"
    assert aliases.green.name == "MypylambdaGreenAlias"


def test_bluegreenaliases(stack: Stack, simple_lambda_function: PyFunction) -> None:
    """Test BlueGreenAliases creation for prod/beta deployment."""
    auto_version = AutoVersion(
        2,
        lambda_function=simple_lambda_function,
    )
    aliases = BlueGreenAliases(
        blue_config=BlueGreenAliasConfiguration(
            version=auto_version.previous,
            name="prod",
            provisioned_concurrency_config=ProvisionedConcurrencyConfiguration(
                ProvisionedConcurrentExecutions=1
            ),
            routing_config=AliasRoutingConfiguration(
                AdditionalVersionWeights=[
                    VersionWeight(
                        FunctionVersion=auto_version.previous.version, FunctionWeight=1
                    )
                ]
            ),
        ),
        green_config=BlueGreenAliasConfiguration(
            version=auto_version.latest,
            name="beta",
            provisioned_concurrency_config=ProvisionedConcurrencyConfiguration(
                ProvisionedConcurrentExecutions=1
            ),
            routing_config=AliasRoutingConfiguration(
                AdditionalVersionWeights=[
                    VersionWeight(
                        FunctionVersion=auto_version.latest.version, FunctionWeight=1
                    )
                ]
            ),
        ),
        lambda_name=simple_lambda_function.name,
        lambda_arn=simple_lambda_function.arn,
    )
    stack.add(aliases)
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_BLUEGREENALIASES_TEMPLATE
    assert aliases.blue.name == "MypylambdaProdAlias"
    assert aliases.green.name == "MypylambdaBetaAlias"


def test_create_flask_wsgi_environ_with_http_api_event():
    # get HTTP API lambda event
    with open(
        os.path.join(SOURCE_DIR, "event-http.json"),  # an event from an HTTP API
    ) as fd:
        rest_api_event = json.load(fd)

    handler = FlaskLambdaHandler("app")
    flask_environment = handler.create_flask_wsgi_environ(rest_api_event, {})

    # remove values that are not
    # JSON serializable
    flask_environment.pop("wsgi.input")
    flask_environment.pop("wsgi.errors")

    # serialize to a JSON dict
    flask_environment = json.loads(json.dumps(flask_environment))

    with open(os.path.join(SOURCE_DIR, "http_api_wsgi_flask_environment.json")) as fd:
        expected_flask_environment = json.load(fd)

    assert flask_environment == expected_flask_environment


def test_create_flask_wsgi_environ_with_rest_api_event():
    # get REST API lambda event
    with open(
        os.path.join(SOURCE_DIR, "event-rest.json"),  # an event from a REST API
    ) as fd:
        rest_api_event = json.load(fd)

    handler = FlaskLambdaHandler("app")
    flask_environment = handler.create_flask_wsgi_environ(rest_api_event, {})

    # remove values that are not
    # JSON serializable
    flask_environment.pop("wsgi.input")
    flask_environment.pop("wsgi.errors")

    # serialize to a JSON dict
    flask_environment = json.loads(json.dumps(flask_environment))

    with open(
        os.path.join(SOURCE_DIR, "rest_api_wsgi_flask_environment.json"),
    ) as fd:
        expected_flask_environment = json.load(fd)

    assert flask_environment == expected_flask_environment


@pytest.fixture
def base64_response_server() -> Iterable[Flask]:
    """Create a server returning a text or base64 encoded response."""
    app = Flask("base64-response")

    @app.route("/text-response", methods=["GET"])
    def get_text_response() -> Response:
        """Return a fake file."""
        return send_file(
            io.BytesIO(b"world"),
            as_attachment=True,
            download_name="hello.txt",
        )

    @app.route("/base64-response", methods=["GET"])
    def get_base64_response() -> Response:
        """Return a fake image.

        The response is base64 encoded in flask_apigateway_wrapper.py because
        the mime type indicates the response contains binary data
        """
        return send_file(
            io.BytesIO("▯PNG␍␊␚␊".encode()),
            as_attachment=True,
            download_name="logo.png",
        )

    app.config.update(
        {
            "TESTING": True,
        }
    )

    yield app


def test_text_response(base64_response_server: Flask) -> None:
    """Query a route sending back a plain text response."""
    with open(
        os.path.join(
            SOURCE_DIR, "event-http-text-response.json"
        ),  # an event from a HTTP API
    ) as fd:
        http_api_event = json.load(fd)

    handler = FlaskLambdaHandler(base64_response_server)
    response = handler.lambda_handler(http_api_event, {})
    # Check the response is not base64
    assert response["statusCode"] == 200
    assert response["headers"]["Content-Type"] == "text/plain; charset=utf-8"
    assert response["body"] == b"world"


def test_base64_response(base64_response_server: Flask) -> None:
    """Query a route sending back a base64 encoded response."""
    with open(
        os.path.join(
            SOURCE_DIR, "event-http-base64-response.json"
        ),  # an event from a HTTP API
    ) as fd:
        http_api_event = json.load(fd)

    handler = FlaskLambdaHandler(base64_response_server)
    response = handler.lambda_handler(http_api_event, {})
    # Check the response is base64 encoded
    assert response["statusCode"] == 200
    assert response["headers"]["Content-Type"] == "image/png"
    assert response["body"] == "4pavUE5H4pCN4pCK4pCa4pCK"


@pytest.mark.parametrize(
    "version, expected_function_name_ref",
    [
        # Add the permission on the function itself
        (
            None,
            "Mypylambda",
        ),
        # Add the permission on a version of the function
        (
            Version(
                name="myversion", description="this is some version", lambda_arn=""
            ),
            "Myversion",
        ),
        # Add the permission on an alias of the function
        (
            Alias(
                name="myalias",
                description="this is some alias",
                lambda_arn="",
                lambda_version="",
            ),
            "Myalias",
        ),
    ],
)
def test_invoke_permission(
    version: Version | Alias | None,
    expected_function_name_ref: str,
) -> None:
    """Test Function.invoke_permission with various targets.

    :param version: a version or alias of the function
    :param expected_function_name_ref: name that should be referenced in FunctionName
    """
    function = Function(
        name="mypylambda",
        description="this is a test",
        role="somearn",
    )

    permission = function.invoke_permission(
        name_suffix="TopicName",
        service="sns",
        source_arn="arn:aws:sns:eu-west-1:123456789012:TopicName",
        version=version,
    )

    assert permission.title == f"{expected_function_name_ref}TopicName"
    assert permission.to_dict() == {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": expected_function_name_ref},
            "Principal": "sns.amazonaws.com",
            "SourceArn": "arn:aws:sns:eu-west-1:123456789012:TopicName",
        },
        "Type": "AWS::Lambda::Permission",
    }
