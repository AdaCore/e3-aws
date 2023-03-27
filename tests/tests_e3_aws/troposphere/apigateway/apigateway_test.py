from __future__ import annotations
import json
import os
import pytest
from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import (
    PyFunction,
    BlueGreenAliases,
    BlueGreenAliasConfiguration,
    AutoVersion,
)
from e3.aws.troposphere.iam.policy_statement import Allow, PolicyStatement
from e3.aws.troposphere.apigateway import (
    JWT_AUTH,
    HttpApi,
    RestApi,
    GET,
    POST,
    Method,
    StageConfiguration,
)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# Generic template without any stage
COMMON_TEMPLATE = {
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": "templates/mypylambda_lambda.zip",
            },
            "Timeout": 3,
            "Description": "this is a test",
            "Role": "somearn",
            "FunctionName": "mypylambda",
            "Runtime": "python3.8",
            "Handler": "app.main",
        },
        "Type": "AWS::Lambda::Function",
    },
    "TestapiLogGroup": {
        "Properties": {"LogGroupName": "testapi"},
        "Type": "AWS::Logs::LogGroup",
    },
    "Testapi": {
        "Properties": {
            "Description": "this is a test",
            "ProtocolType": "HTTP",
            "Name": "testapi",
            "DisableExecuteApiEndpoint": False,
        },
        "Type": "AWS::ApiGatewayV2::Api",
    },
    "TestapiIntegration": {
        "Properties": {
            "ApiId": {"Ref": "Testapi"},
            "IntegrationType": "AWS_PROXY",
            "IntegrationUri": {"Ref": "Mypylambda"},
            "PayloadFormatVersion": "2.0",
        },
        "Type": "AWS::ApiGatewayV2::Integration",
    },
    "TestapiGETapi1Route": {
        "Properties": {
            "ApiId": {"Ref": "Testapi"},
            "AuthorizationType": "NONE",
            "RouteKey": "GET /api1",
            "Target": {
                "Fn::Sub": [
                    "integrations/${integration}",
                    {"integration": {"Ref": "TestapiIntegration"}},
                ]
            },
        },
        "Type": "AWS::ApiGatewayV2::Route",
    },
    "TestapiPOSTapi2Route": {
        "Properties": {
            "ApiId": {"Ref": "Testapi"},
            "AuthorizationType": "NONE",
            "RouteKey": "POST /api2",
            "Target": {
                "Fn::Sub": [
                    "integrations/${integration}",
                    {"integration": {"Ref": "TestapiIntegration"}},
                ]
            },
        },
        "Type": "AWS::ApiGatewayV2::Route",
    },
}

# Generic stage template with common values
COMMON_STAGE_TEMPLATE = {
    "AccessLogSettings": {
        "DestinationArn": {"Fn::GetAtt": ["TestapiLogGroup", "Arn"]},
        "Format": '{"source_ip": "$context.identity.sourceIp", '
        '"request_time": "$context.requestTime", '
        '"method": "$context.httpMethod", "route": "$context.routeKey", '
        '"protocol": "$context.protocol", "status": "$context.status", '
        '"response_length": "$context.responseLength", '
        '"request_id": "$context.requestId", '
        '"integration_error_msg": "$context.integrationErrorMessage"}',
    },
    "ApiId": {"Ref": "Testapi"},
    "AutoDeploy": True,
    "DefaultRouteSettings": {
        "DetailedMetricsEnabled": True,
        "ThrottlingBurstLimit": 10,
        "ThrottlingRateLimit": 10,
    },
}

# API with a $default stage
EXPECTED_TEMPLATE = {
    **COMMON_TEMPLATE,
    "TestapiGETapi1LambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "Mypylambda"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:"
                    "${AWS::AccountId}:${api}/$default/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "GET/api1"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiPOSTapi2LambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "Mypylambda"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:"
                    "${AWS::AccountId}:${api}/$default/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "POST/api2"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiDefaultStage": {
        "Properties": {
            **COMMON_STAGE_TEMPLATE,
            "Description": "stage $default",
            "StageName": "$default",
        },
        "Type": "AWS::ApiGatewayV2::Stage",
    },
}

# API with $default/beta stages
EXPECTED_TEMPLATE_STAGE = {
    **EXPECTED_TEMPLATE,
    "TestapiGETapi1BetaLambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "Mypylambda"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/beta/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "GET/api1"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiPOSTapi2BetaLambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "Mypylambda"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/beta/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "POST/api2"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiBetaStage": {
        "Properties": {
            **COMMON_STAGE_TEMPLATE,
            "Description": "stage beta",
            "StageName": "beta",
            "StageVariables": {"somevar": "somevalue"},
        },
        "Type": "AWS::ApiGatewayV2::Stage",
    },
}

# API with $default/beta stages and lambdaAlias variable
EXPECTED_TEMPLATE_LAMBDA_ALIAS = {
    **COMMON_TEMPLATE,
    "TestapiGETapi1LambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "MypylambdaBlueAlias"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/$default/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "GET/api1"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiPOSTapi2LambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "MypylambdaBlueAlias"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/$default/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "POST/api2"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiGETapi1BetaLambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "MypylambdaGreenAlias"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/beta/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "GET/api1"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiPOSTapi2BetaLambdaPermission": {
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "MypylambdaGreenAlias"},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": {
                "Fn::Sub": [
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/beta/${route_arn}",
                    {"api": {"Ref": "Testapi"}, "route_arn": "POST/api2"},
                ]
            },
        },
        "Type": "AWS::Lambda::Permission",
    },
    "TestapiDefaultStage": {
        "Properties": {
            **COMMON_STAGE_TEMPLATE,
            "Description": "stage $default",
            "StageName": "$default",
            "StageVariables": {"lambdaAlias": "MypylambdaBlueAlias"},
        },
        "Type": "AWS::ApiGatewayV2::Stage",
    },
    "TestapiBetaStage": {
        "Properties": {
            **COMMON_STAGE_TEMPLATE,
            "Description": "stage beta",
            "StageName": "beta",
            "StageVariables": {"lambdaAlias": "MypylambdaGreenAlias"},
        },
        "Type": "AWS::ApiGatewayV2::Stage",
    },
    "TestapiIntegration": {
        "Properties": {
            **EXPECTED_TEMPLATE["TestapiIntegration"]["Properties"],
            "IntegrationUri": "arn:aws:lambda:eu-west-1:123456789012:function:"
            "mypylambda:${stageVariables.lambdaAlias}",
        },
        "Type": "AWS::ApiGatewayV2::Integration",
    },
}


@pytest.fixture
def lambda_fun() -> PyFunction:
    """Return a simple lambda function for testing."""
    return PyFunction(
        name="mypylambda",
        description="this is a test",
        role="somearn",
        code_dir="my_code_dir",
        handler="app.main",
        runtime="python3.8",
        logs_retention_in_days=None,
    )


def test_http_api(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test basic HTTP API."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    stack.add(lambda_fun)
    stack.add(
        HttpApi(
            name="testapi",
            description="this is a test",
            lambda_arn=lambda_fun.ref,
            route_list=[GET(route="/api1"), POST(route="/api2")],
        )
    )

    assert stack.export()["Resources"] == EXPECTED_TEMPLATE


def test_http_api_stage(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test HTTP API with stages."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    http_api = HttpApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        route_list=[GET(route="/api1"), POST(route="/api2")],
        stages_config=[
            StageConfiguration("$default"),
            StageConfiguration("beta", variables={"somevar": "somevalue"}),
        ],
    )

    stack.add(lambda_fun)
    stack.add(http_api)

    assert stack.export()["Resources"] == EXPECTED_TEMPLATE_STAGE


def test_http_api_lambda_alias(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test HTTP API with lambda alias."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    lambda_versions = AutoVersion(2, lambda_function=lambda_fun)

    lambda_aliases = BlueGreenAliases(
        blue_config=BlueGreenAliasConfiguration(
            version=lambda_versions.previous.version
        ),
        green_config=BlueGreenAliasConfiguration(
            version=lambda_versions.latest.version
        ),
        lambda_function=lambda_fun,
    )

    http_api = HttpApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        route_list=[GET(route="/api1"), POST(route="/api2")],
        stages_config=[
            StageConfiguration(
                "$default",
                lambda_arn_permission=lambda_aliases.blue.ref,
                variables={"lambdaAlias": lambda_aliases.blue.name},
            ),
            StageConfiguration(
                "beta",
                lambda_arn_permission=lambda_aliases.green.ref,
                variables={"lambdaAlias": lambda_aliases.green.name},
            ),
        ],
        integration_uri="arn:aws:lambda:eu-west-1:123456789012:function:"
        f"{lambda_fun.name}:${{stageVariables.lambdaAlias}}",
    )

    stack.add(lambda_fun)
    stack.add(http_api)

    assert stack.export()["Resources"] == EXPECTED_TEMPLATE_LAMBDA_ALIAS


def test_http_api_custom_domain(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test basic HTTP API with custom domain."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    stack.add(lambda_fun)
    http_api = HttpApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        domain_name="api.example.com",
        hosted_zone_id="ABCDEFG",
        route_list=[
            GET(route="/api1"),
            POST(route="/api2"),
            GET("/api3", auth=JWT_AUTH, authorizer_name="testauthorizer"),
        ],
    )
    http_api.add_jwt_authorizer(
        name="testauthorizer",
        audience=["testaudience"],
        issuer="https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test",
    )
    stack.add(http_api)

    with open(os.path.join(TEST_DIR, "apigateway_test_custom_domain.json")) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_http_api_multi_domains(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test basic HTTP API with two domains."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    stack.add(lambda_fun)
    http_api = HttpApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        domain_name="api.example.com",
        hosted_zone_id="ABCDEFG",
        route_list=[
            GET(route="/api1"),
            POST(route="/api2"),
        ],
    )
    stack.add(http_api)
    for el in http_api.declare_domain(
        domain_name="api2.example.com", hosted_zone_id="BCDEFGH"
    ):
        stack.add(el)

    with open(os.path.join(TEST_DIR, "apigateway_test_multi_domains.json")) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_http_api_custom_domain_stages(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test basic HTTP API with custom domain and stage."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    stack.add(lambda_fun)
    http_api = HttpApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        domain_name="api.example.com",
        hosted_zone_id="ABCDEFG",
        route_list=[
            GET(route="/api1"),
            POST(route="/api2"),
            GET("/api3", auth=JWT_AUTH, authorizer_name="testauthorizer"),
        ],
        stages_config=[
            StageConfiguration("$default"),
            StageConfiguration("beta", api_mapping_key="beta"),
        ],
    )
    http_api.add_jwt_authorizer(
        name="testauthorizer",
        audience=["testaudience"],
        issuer="https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test",
    )
    stack.add(http_api)

    with open(
        os.path.join(TEST_DIR, "apigateway_test_custom_domain_stages.json")
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_custom_domain_stages(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST api custom domain and stage."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    stack.add(lambda_fun)
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        domain_name="api.example.com",
        hosted_zone_id="ABCDEFG",
        method_list=[
            Method("ANY", authorizer_name="testauthorizer"),
        ],
        stages_config=[
            StageConfiguration("$default"),
            StageConfiguration(
                "beta", api_mapping_key="beta", variables={"somevar": "somevalue"}
            ),
        ],
        policy=[
            Allow(
                principal="*",
                action=[
                    "execute-api:Invoke",
                ],
                resource="execute-api:/*/*/*",
            ),
            # allow API invocation only from a specific IP
            PolicyStatement(
                effect="Deny",
                principal="*",
                action="execute-api:Invoke",
                resource="execute-api:/*/*/*",
                condition={"NotIpAddress": {"aws:SourceIp": ["1.2.3.4"]}},
            ),
        ],
    )
    rest_api.add_jwt_authorizer(
        name="testauthorizer",
        providers_arn=[
            "arn:aws:cognito-idp:eu-west-1:123456789012:userpool/eu-west-1_abc123"
        ],
    )
    stack.add(rest_api)
    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_custom_domain_stages.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected
