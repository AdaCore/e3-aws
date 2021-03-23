from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from troposphere import apigatewayv2, Ref, logs, GetAtt, awslambda, Sub
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from troposphere import AWSObject
import json

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack


class HttpApi(Construct):
    def __init__(
        self,
        name: str,
        description: str,
        lambda_arn: str | GetAtt | Ref,
        route_list: list[tuple[str, str]],
        burst_limit: int = 10,
        rate_limit: int = 10,
    ):
        """Initialize an HTTP API.

        The schema supported here is a single lambda handling all the routes.
        Nevertherless, we don't use {proxy}+ route and rather declare
        statically the list of supported route. This ensure that our lambda is
        not executed whenever an invalid route is invoked. Thus the cost of invoking
        an invalid route is 0.

        The API use only one stage ($default)

        :param name: the resource name
        :param lambda_arn: arn of the lambda executed for all routes
        :param route_list: a list of route to declare
        :param burst_limit: maximum concurrent requests at a given time
            (exceeding that limit will cause API Gateway to return 429)
        :param rate_limit: maximum number of requests per seconds
        """
        self.name = name
        self.description = description
        self.lambda_arn = lambda_arn
        self.route_list = route_list
        self.burst_limit = burst_limit
        self.rate_limit = rate_limit

    def cfn_policy_document(self, stack: Stack) -> PolicyDocument:
        """Get policy needed by CloudFormation."""
        return PolicyDocument(
            [
                PolicyStatement(
                    action=["logs:DescribeLogGroups", "logs:CreateLogGroup"],
                    effect="Allow",
                    resource=f"arn:aws:logs:::log-group:{self.name}",
                )
            ]
        )

    def declare_stage(
        self, stage_name: str, log_arn: str | GetAtt
    ) -> apigatewayv2.Stage:
        """Declare an API gateway stage.

        :param stage_name: name of the stage
        :param log_arn: arn of the cloudwatch log group in which api calls
            should be logged
        :return: the AWSObject corresponding to the Stage
        """
        logical_id = name_to_id(self.name)

        log_format = {
            "source_ip": "$context.identity.sourceIp",
            "request_time": "$context.requestTime",
            "method": "$context.httpMethod",
            "route": "$context.routeKey",
            "protocol": "$context.protocol",
            "status": "$context.status",
            "response_length": "$context.responseLength",
            "request_id": "$context.requestId",
            "integration_error_msg": "$context.integrationErrorMessage",
        }

        access_log_settings = apigatewayv2.AccessLogSettings(
            DestinationArn=GetAtt(logical_id + "LogGroup", "Arn"),
            Format=json.dumps(log_format),
        )

        route_settings = apigatewayv2.RouteSettings(
            DetailedMetricsEnabled=True,
            ThrottlingBurstLimit=self.burst_limit,
            ThrottlingRateLimit=self.rate_limit,
        )

        return apigatewayv2.Stage(
            logical_id + name_to_id(stage_name) + "Stage",
            AccessLogSettings=access_log_settings,
            ApiId=Ref(logical_id),
            AutoDeploy=True,
            Description=f"stage {stage_name}",
            DefaultRouteSettings=route_settings,
            StageName=stage_name,
        )

    def declare_route(
        self, method: str, route: str, integration: Ref | str
    ) -> list[AWSObject]:
        """Declare a route.

        :param method: the https method to use (GET, POST, ...)
        :param route: the route (starting with /)
        :param integration: arn of the integration to use for this route
        :return: a list of AWSObjects to be added to the stack
        """
        assert route.startswith("/")
        result = []
        api_id = name_to_id(self.name)
        id_prefix = name_to_id(self.name + method + route)
        result.append(
            apigatewayv2.Route(
                id_prefix + "Route",
                ApiId=Ref(api_id),
                AuthorizationType="NONE",
                RouteKey=f"{method} {route}",
                Target=Sub(
                    "integrations/${integration}",
                    dict_values={"integration": integration},
                ),
            )
        )

        result.append(
            awslambda.Permission(
                id_prefix + "LambdaPermission",
                Action="lambda:InvokeFunction",
                FunctionName=self.lambda_arn,
                Principal="apigateway.amazonaws.com",
                SourceArn=Sub(
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/$default/${route_arn}",
                    dict_values={"api": Ref(api_id), "route_arn": f"{method}{route}"},
                ),
            )
        )
        return result

    def resources(self, stack: Stack) -> list[AWSObject]:
        # API logical id
        logical_id = name_to_id(self.name)

        result = []

        # Create a log group for the API
        result.append(logs.LogGroup(logical_id + "LogGroup", LogGroupName=self.name))

        # Create the API itself
        api_params = {
            "Description": self.description,
            "ProtocolType": "HTTP",
            "Name": self.name,
        }
        result.append(apigatewayv2.Api(name_to_id(self.name), **api_params))

        # Declare the default stage
        result.append(
            self.declare_stage(
                stage_name="$default", log_arn=GetAtt(logical_id + "LogGroup", "Arn")
            )
        )

        # Declare one integration
        result.append(
            apigatewayv2.Integration(
                logical_id + "Integration",
                ApiId=Ref(logical_id),
                IntegrationType="AWS_PROXY",
                IntegrationUri=self.lambda_arn,
                PayloadFormatVersion="2.0",
            )
        )

        # Declare the routes
        for method, route in self.route_list:
            result += self.declare_route(
                method=method, route=route, integration=Ref(logical_id + "Integration")
            )

        return result
