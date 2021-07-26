from __future__ import annotations
import json
import os
from e3.aws.troposphere import Stack
from e3.aws.troposphere.awslambda import Py38Function
from e3.aws.troposphere.apigateway import JWT_AUTH, HttpApi, GET, POST

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

EXPECTED_TEMPLATE = {
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
    "TestapiDefaultStage": {
        "Properties": {
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
            "Description": "stage $default",
            "DefaultRouteSettings": {
                "DetailedMetricsEnabled": True,
                "ThrottlingBurstLimit": 10,
                "ThrottlingRateLimit": 10,
            },
            "StageName": "$default",
        },
        "Type": "AWS::ApiGatewayV2::Stage",
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
}


def test_http_api(stack: Stack) -> None:
    """Test basic HTTP API."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    lambda_fun = Py38Function(
        name="mypylambda",
        description="this is a test",
        role="somearn",
        code_dir="my_code_dir",
        handler="app.main",
    )
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


def test_http_api_custom_domain(stack: Stack) -> None:
    """Test basic HTTP API with custom domain."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"

    lambda_fun = Py38Function(
        name="mypylambda",
        description="this is a test",
        role="somearn",
        code_dir="my_code_dir",
        handler="app.main",
    )
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
