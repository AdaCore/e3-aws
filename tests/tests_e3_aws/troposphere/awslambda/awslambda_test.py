from __future__ import annotations
import base64
import docker
import os

from e3.aws import AWSEnv
from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import PyFunction, Py38Function, DockerFunction


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
