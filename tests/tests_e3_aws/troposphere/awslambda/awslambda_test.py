from __future__ import annotations
import base64
import docker
import os
import pytest
import json

from troposphere.awslambda import (
    ProvisionedConcurrencyConfiguration,
    AliasRoutingConfiguration,
    VersionWeight,
)

from e3.aws import AWSEnv
from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import (
    PyFunction,
    Py38Function,
    DockerFunction,
    Alias,
    Version,
    AutoVersion,
    BlueGreenAliases,
    BlueGreenAliasConfiguration,
)
from e3.aws.troposphere.awslambda.flask_apigateway_wrapper import FlaskLambdaHandler

SOURCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "source_dir")


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

EXPECTED_BLUEGREENALIASES_DEFAULT_TEMPLATE = {
    "MypylambdaBlueAlias": {
        "Properties": {
            "Name": "MypylambdaBlueAlias",
            "Description": "blue alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Ref": "MypylambdaVersion1"},
        },
        "Type": "AWS::Lambda::Alias",
    },
    "MypylambdaGreenAlias": {
        "Properties": {
            "Name": "MypylambdaGreenAlias",
            "Description": "green alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Ref": "MypylambdaVersion2"},
        },
        "Type": "AWS::Lambda::Alias",
    },
}

EXPECTED_BLUEGREENALIASES_TEMPLATE = {
    "MypylambdaProdAlias": {
        "Properties": {
            "Name": "MypylambdaProdAlias",
            "Description": "prod alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Ref": "MypylambdaVersion1"},
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
            "Name": "MypylambdaBetaAlias",
            "Description": "beta alias for mypylambda lambda",
            "FunctionName": {"Fn::GetAtt": ["Mypylambda", "Arn"]},
            "FunctionVersion": {"Ref": "MypylambdaVersion2"},
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
        )
    )
    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == EXPECTED_PYFUNCTION_TEMPLATE


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


def test_docker_function(stack: Stack) -> None:
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
    assert auto_version.previous.name == "mypylambdaVersion2"
    assert auto_version.latest.name == "mypylambdaVersion3"


def test_bluegreenaliases_default(
    stack: Stack, simple_lambda_function: PyFunction
) -> None:
    """Test BlueGreenAliases creation with default settings."""
    auto_version = AutoVersion(
        2,
        lambda_function=simple_lambda_function,
    )
    aliases = BlueGreenAliases(
        blue_config=BlueGreenAliasConfiguration(version=auto_version.previous.ref),
        green_config=BlueGreenAliasConfiguration(version=auto_version.latest.ref),
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
            version=auto_version.previous.ref,
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
            version=auto_version.latest.ref,
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


def test_create_flask_wsgi_environ_with_rest_api_event():
    # get REST API lambda event
    with open(
        os.path.join(SOURCE_DIR, "event.json"),  # an event from a REST API
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
