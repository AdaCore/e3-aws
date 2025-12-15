from __future__ import annotations
from typing import Any, cast
import logging
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
    Resource,
    StageConfiguration,
    EndpointConfigurationType,
    IpAddressType,
    EndpointAccessMode,
    SecurityPolicy,
    SecurityPolicyLookup,
)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# Generic template without any stage
COMMON_TEMPLATE = {
    "Mypylambda": {
        "Properties": {
            "Code": {
                "S3Bucket": "cfn_bucket",
                "S3Key": {
                    "Fn::Sub": "assets/${MypylambdaSourcesS3Key}",
                },
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
            **cast(
                dict[str, Any], EXPECTED_TEMPLATE["TestapiIntegration"]["Properties"]
            ),
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


def test_http_api_stages(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test HTTP API with stages."""
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


def test_rest_api(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test basic REST API."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[
            Method("ANY"),
        ],
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_stages(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST API with stages."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[
            Method("ANY"),
        ],
        stages_config=[
            StageConfiguration("default"),
            StageConfiguration(
                "beta", api_mapping_key="beta", variables={"somevar": "somevalue"}
            ),
        ],
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_stages.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_lambda_alias(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST API with lambda alias."""
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

    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[
            Method("ANY"),
        ],
        stages_config=[
            StageConfiguration(
                "default",
                lambda_arn_permission=lambda_aliases.blue.ref,
                variables={"lambdaAlias": lambda_aliases.blue.name},
            ),
            StageConfiguration(
                "beta",
                lambda_arn_permission=lambda_aliases.green.ref,
                variables={"lambdaAlias": lambda_aliases.green.name},
            ),
        ],
        integration_uri="arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/"
        f"functions/arn:aws:lambda:us-east-1:123456789012:function:"
        f"{lambda_fun.name}:${{stageVariables.lambdaAlias}}/invocations",
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_lambda_alias.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_custom_domain(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST api custom domain."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        domain_name="api.example.com",
        hosted_zone_id="ABCDEFG",
        method_list=[
            Method("ANY", authorizer_name="testauthorizer"),
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
        # Compression can be enabled this way
        minimum_compression_size=0,
        # Some media type can be treated as binary data
        binary_media_types=["image/png"],
    )
    rest_api.add_cognito_authorizer(
        name="testauthorizer",
        providers_arn=[
            "arn:aws:cognito-idp:eu-west-1:123456789012:userpool/eu-west-1_abc123"
        ],
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_custom_domain.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_custom_domain_stages(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST api custom domain and stage."""
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
            StageConfiguration("default"),
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
        # Compression can be enabled this way
        minimum_compression_size=0,
        # Some media type can be treated as binary data
        binary_media_types=["image/png"],
    )
    rest_api.add_cognito_authorizer(
        name="testauthorizer",
        providers_arn=[
            "arn:aws:cognito-idp:eu-west-1:123456789012:userpool/eu-west-1_abc123"
        ],
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_custom_domain_stages.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_nested_resources(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST API with nested resources."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        resource_list=[
            Resource(
                path="foo",
                method_list=[Method("ANY")],
                resource_list=[Resource(path="bar", method_list=[Method("GET")])],
            ),
        ],
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_nested_resources.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_multi_lambdas_stages(stack: Stack) -> None:
    """Test REST API with multiple lambdas and stages."""
    # Create two lambdas for two different methods
    accounts_lambda, products_lambda = [
        PyFunction(
            name=f"{name}lambda",
            description="this is a test",
            role="somearn",
            code_dir="my_code_dir",
            handler="app.main",
            runtime="python3.8",
            logs_retention_in_days=None,
        )
        for name in ("accounts", "products")
    ]

    # Create lambda versions
    accounts_lambda_versions, products_lambda_versions = [
        AutoVersion(2, lambda_function=lambda_fun)
        for lambda_fun in (accounts_lambda, products_lambda)
    ]

    # Create lambda aliases.
    # Share the same alias names as it will make it easier to setup the stage
    # variable for using the right alias depending on the stage
    accounts_lambda_aliases, products_lambda_aliases = [
        BlueGreenAliases(
            blue_config=BlueGreenAliasConfiguration(
                name="Blue", version=lambda_versions.previous.version
            ),
            green_config=BlueGreenAliasConfiguration(
                name="Green", version=lambda_versions.latest.version
            ),
            lambda_function=lambda_fun,
        )
        for lambda_versions, lambda_fun in (
            (accounts_lambda_versions, accounts_lambda),
            (products_lambda_versions, products_lambda),
        )
    ]

    # Create the REST API
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        # Not important as it's overriden in resources
        lambda_arn=accounts_lambda.ref,
        # Declare prod and beta stages redirecting to correct aliases
        stages_config=[
            StageConfiguration("default", variables={"lambdaAlias": "Blue"}),
            StageConfiguration("beta", variables={"lambdaAlias": "Green"}),
        ],
        # Declare two resources pointing to two different lambdas
        resource_list=[
            Resource(
                path=path,
                # Action to invoke the lambda with correct alias
                integration_uri="arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/"
                "functions/arn:aws:lambda:eu-west-1:123456789012:function:"
                f"{lambda_fun.name}:${{stageVariables.lambdaAlias}}/invocations",
                # Lambda ARNs for InvokeFunction permissions depending on the stage
                lambda_arn_permission={
                    "default": lambda_aliases.blue.ref,
                    "beta": lambda_aliases.green.ref,
                },
                method_list=[Method("ANY")],
            )
            for path, lambda_fun, lambda_aliases in (
                ("accounts", accounts_lambda, accounts_lambda_aliases),
                ("products", products_lambda, products_lambda_aliases),
            )
        ],
    )

    stack.add(accounts_lambda)
    stack.add(products_lambda)
    stack.add(accounts_lambda_versions)
    stack.add(products_lambda_versions)
    stack.add(accounts_lambda_aliases)
    stack.add(products_lambda_aliases)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_multi_lambdas_stages.json"),
    ) as fd:
        expected = json.load(fd)

    print(stack.export()["Resources"])
    assert stack.export()["Resources"] == expected


def test_rest_api_endpoint_configuration_regional(
    stack: Stack, lambda_fun: PyFunction
) -> None:
    """Test REST API with REGIONAL endpoint configuration."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        endpoint_configuration_type=EndpointConfigurationType.REGIONAL,
        ip_address_type=IpAddressType.IPV4,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_regional_endpoint.json"),
    ) as fd:
        expected = json.load(fd)

    assert stack.export()["Resources"] == expected


def test_rest_api_endpoint_configuration_edge(
    stack: Stack, lambda_fun: PyFunction
) -> None:
    """Test REST API with EDGE endpoint configuration and DUAL_STACK IP."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        endpoint_configuration_type=EndpointConfigurationType.EDGE,
        ip_address_type=IpAddressType.DUAL_STACK,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_edge_endpoint.json"),
    ) as fd:
        expected = json.load(fd)

    assert stack.export()["Resources"] == expected


def test_rest_api_endpoint_access_mode(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST API with endpoint access mode and security policy."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        endpoint_access_mode=EndpointAccessMode.STRICT,
        security_policy=SecurityPolicy.SECURITYPOLICY_TLS13_1_2_2021_06,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_endpoint_access_mode.json"),
    ) as fd:
        expected = json.load(fd)

    assert stack.export()["Resources"] == expected


def test_rest_api_integration_timeout(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST API with custom integration timeout."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        integration_timeout=10000,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_integration_timeout.json"),
    ) as fd:
        expected = json.load(fd)

    assert stack.export()["Resources"] == expected


def test_rest_api_regional_custom_domain(stack: Stack, lambda_fun: PyFunction) -> None:
    """Test REST API with REGIONAL endpoint and custom domain."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        domain_name="api.example.com",
        hosted_zone_id="ABCDEFG",
        method_list=[Method("ANY")],
        endpoint_configuration_type=EndpointConfigurationType.REGIONAL,
        security_policy=SecurityPolicy.SECURITYPOLICY_TLS13_1_3_2025_09,
        endpoint_access_mode=EndpointAccessMode.BASIC,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_regional_custom_domain.json"),
    ) as fd:
        expected = json.load(fd)

    assert stack.export()["Resources"] == expected


def test_rest_api_security_policy_legacy_warning(
    stack: Stack, lambda_fun: PyFunction, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that legacy security policies produce a warning."""
    caplog.set_level(logging.WARNING)

    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        security_policy=SecurityPolicy.TLS_1_2,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    # Check that a warning was logged about legacy security policy
    assert any(
        "legacy security policy" in record.message.lower() for record in caplog.records
    )


def test_rest_api_security_policy_incompatible_warning(
    stack: Stack, lambda_fun: PyFunction, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that incompatible security policy produces a warning."""
    caplog.set_level(logging.WARNING)

    # Verify no warning exists before creating the RestApi
    assert not any(
        "may not be compatible" in record.message.lower() for record in caplog.records
    )

    # Use EDGE security policy with REGIONAL endpoint (incompatible)
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        endpoint_configuration_type=EndpointConfigurationType.REGIONAL,
        security_policy=SecurityPolicy.SECURITYPOLICY_TLS12_2018_EDGE,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    # Check that a warning was logged about incompatible security policy
    assert any(
        "may not be compatible" in record.message.lower() for record in caplog.records
    )


def test_rest_api_endpoint_configuration_type_only(
    stack: Stack, lambda_fun: PyFunction
) -> None:
    """Test REST API with only endpoint_configuration_type (no ip_address_type)."""
    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        endpoint_configuration_type=EndpointConfigurationType.PRIVATE,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    with open(
        os.path.join(TEST_DIR, "apigatewayv1_test_private_endpoint.json"),
    ) as fd:
        expected = json.load(fd)

    assert stack.export()["Resources"] == expected


@pytest.mark.parametrize(
    "endpoint_type,security_policy,should_be_valid",
    [
        # Valid REGIONAL policies
        (
            EndpointConfigurationType.REGIONAL,
            SecurityPolicy.SECURITYPOLICY_TLS13_1_2_2021_06,
            True,
        ),
        (
            EndpointConfigurationType.REGIONAL,
            SecurityPolicy.TLS_1_2,
            True,
        ),
        # Invalid: EDGE policy with REGIONAL endpoint
        (
            EndpointConfigurationType.REGIONAL,
            SecurityPolicy.SECURITYPOLICY_TLS12_2018_EDGE,
            False,
        ),
        # Valid EDGE policies
        (
            EndpointConfigurationType.EDGE,
            SecurityPolicy.SECURITYPOLICY_TLS13_2025_EDGE,
            True,
        ),
        (
            EndpointConfigurationType.EDGE,
            SecurityPolicy.TLS_1_0,
            True,
        ),
        # Invalid: REGIONAL policy with EDGE endpoint
        (
            EndpointConfigurationType.EDGE,
            SecurityPolicy.SECURITYPOLICY_TLS13_1_2_2021_06,
            False,
        ),
        # Valid PRIVATE policies
        (
            EndpointConfigurationType.PRIVATE,
            SecurityPolicy.SECURITYPOLICY_TLS13_1_3_2025_09,
            True,
        ),
        # Invalid: EDGE policy with PRIVATE endpoint
        (
            EndpointConfigurationType.PRIVATE,
            SecurityPolicy.SECURITYPOLICY_TLS13_2025_EDGE,
            False,
        ),
    ],
)
def test_rest_api_security_policy_validation(
    stack: Stack,
    lambda_fun: PyFunction,
    caplog: pytest.LogCaptureFixture,
    endpoint_type: EndpointConfigurationType,
    security_policy: SecurityPolicy,
    should_be_valid: bool,
) -> None:
    """Test security policy validation against endpoint configuration types."""
    caplog.set_level(logging.WARNING)

    # Verify our test data matches the SecurityPolicyLookup
    is_valid_in_lookup = security_policy in SecurityPolicyLookup[endpoint_type]
    assert is_valid_in_lookup == should_be_valid, (
        f"Test data mismatch: {security_policy.name} with {endpoint_type.name} "
        f"should be {'valid' if should_be_valid else 'invalid'}"
    )

    rest_api = RestApi(
        name="testapi",
        description="this is a test",
        lambda_arn=lambda_fun.ref,
        method_list=[Method("ANY")],
        endpoint_configuration_type=endpoint_type,
        security_policy=security_policy,
    )

    stack.add(lambda_fun)
    stack.add(rest_api)

    # Check for compatibility warning
    has_compatibility_warning = any(
        "may not be compatible" in record.message.lower() for record in caplog.records
    )

    if should_be_valid:
        assert not has_compatibility_warning, (
            f"Should not warn for valid combination: "
            f"{security_policy.name} with {endpoint_type.name}"
        )
    else:
        assert has_compatibility_warning, (
            f"Should warn for invalid combination: "
            f"{security_policy.name} with {endpoint_type.name}"
        )
