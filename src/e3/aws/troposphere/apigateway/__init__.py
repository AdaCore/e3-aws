from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from troposphere import apigatewayv2, route53, Ref, logs, GetAtt, awslambda, Sub
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement
from troposphere import AWSObject
from troposphere.certificatemanager import Certificate, DomainValidationOption
import json

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack
    from typing import Any, Optional


class AuthorizationType(Enum):
    """Allowed authorization types for ApiGateway routes."""

    NONE = "NONE"
    JWT = "JWT"
    IAM = "AWS_IAM"
    CUSTOM = "CUSTOM"


# Declare some constants to make declarations more concise.
NO_AUTH = AuthorizationType.NONE
JWT_AUTH = AuthorizationType.JWT
IAM_AUTH = AuthorizationType.IAM
CUSTOM_AUTH = AuthorizationType.CUSTOM


class Route:
    """API Gateway route definition."""

    def __init__(
        self,
        method: str,
        route: str,
        auth: AuthorizationType = NO_AUTH,
        authorizer_name: Optional[str] = None,
    ) -> None:
        """Initialize an API Gateway route definition.

        :param method: the https method
        :param route: the route (should start with a "/")
        :param auth: the authorization type associated with the route
        :param authorizer_name: the name of the authorizer to use
            (used only when using JWT_AUTH)
        """
        assert route.startswith("/"), "route path should starts with a /"
        self.method = method
        self.route = route
        self.auth = auth
        self.authorizer_name = authorizer_name


class GET(Route):
    """An API Gateway GET route."""

    def __init__(
        self,
        route: str,
        auth: AuthorizationType = NO_AUTH,
        authorizer_name: Optional[str] = None,
    ) -> None:
        """Initialize a GET route.

        :param route: the route (should start with a "/")
        :param auth: the authorization type associated with the route
        :param authorizer_name: the name of the authorizer to use
            (used only when using JWT_AUTH)
        """
        super().__init__(
            method="GET", route=route, auth=auth, authorizer_name=authorizer_name
        )


class POST(Route):
    """An API Gateway POST route."""

    def __init__(
        self,
        route: str,
        auth: AuthorizationType = NO_AUTH,
        authorizer_name: Optional[str] = None,
    ) -> None:
        """Initialize a POST route.

        :param route: the route (should start with a "/")
        :param auth: the authorization type associated with the route
        :param authorizer_name: the name of the authorizer to use
            (used only when using JWT_AUTH)
        """
        super().__init__(
            method="POST", route=route, auth=auth, authorizer_name=authorizer_name
        )


class HttpApi(Construct):
    """HTTP API support."""

    def __init__(
        self,
        name: str,
        description: str,
        lambda_arn: str | GetAtt | Ref,
        route_list: list[Route],
        burst_limit: int = 10,
        rate_limit: int = 10,
        domain_name: Optional[str] = None,
        hosted_zone_id: Optional[str] = None,
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
        :param domain_name: if domain_name is not None then associate the API
            with a given domain name. In that case a certificate is
            automatically created for that domain name. Note that if a domain
            name is specified then the default endpoint (execute-api) is
            disabled.
        :param hosted_zone_id: id of the hosted zone that contains domain_name.
            This parameter is required if domain_name is not None
        """
        self.name = name
        self.description = description
        self.lambda_arn = lambda_arn
        self.route_list = route_list
        self.burst_limit = burst_limit
        self.rate_limit = rate_limit
        self.domain_name = domain_name
        self.disable_execute_api_endpoint: bool = False
        if self.domain_name is not None:
            self.disable_execute_api_endpoint = True
            assert (
                hosted_zone_id is not None
            ), "hosted zone id required when domain_name is not None"
        self.hosted_zone_id = hosted_zone_id
        self.authorizers: dict[str, Any] = {}

    def add_jwt_authorizer(
        self, name: str, audience: list[str], issuer: str, header: str = "Authorization"
    ) -> None:
        """Declare a JWT authorizer.

        :param name: authorizer name
        :param audience: a list of accepted audience. For most cases this is the list
            of accepted Cognito client ids.
        :param issuer: the base domain of the entity provider. If Cognito is used this
            is https://cognito-idp.{region}.amazonaws.com/{userPoolId}
        """
        self.authorizers[name] = {
            "ApiId": self.ref,
            "AuthorizerType": "JWT",
            "Name": name,
            "IdentitySource": [f"$request.header.{header}"],
            "JwtConfiguration": apigatewayv2.JWTConfiguration(
                Audience=audience, Issuer=issuer
            ),
        }

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

    def declare_route(self, route: Route, integration: Ref | str) -> list[AWSObject]:
        """Declare a route.

        :param route: the route definition
        :param integration: arn of the integration to use for this route
        :return: a list of AWSObjects to be added to the stack
        """
        result = []
        id_prefix = name_to_id(self.name + route.method + route.route)

        route_params = {
            "ApiId": self.ref,
            "AuthorizationType": route.auth.value,
            "RouteKey": f"{route.method} {route.route}",
            "Target": Sub(
                "integrations/${integration}", dict_values={"integration": integration}
            ),
        }
        if route.authorizer_name:
            route_params["AuthorizerId"] = Ref(name_to_id(route.authorizer_name))

        result.append(apigatewayv2.Route(id_prefix + "Route", **route_params))

        result.append(
            awslambda.Permission(
                id_prefix + "LambdaPermission",
                Action="lambda:InvokeFunction",
                FunctionName=self.lambda_arn,
                Principal="apigateway.amazonaws.com",
                SourceArn=Sub(
                    "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                    "${api}/$default/${route_arn}",
                    dict_values={
                        "api": self.ref,
                        "route_arn": f"{route.method}{route.route}",
                    },
                ),
            )
        )
        return result

    def declare_domain(
        self, domain_name: str, hosted_zone_id: str, stage_name: str
    ) -> list[AWSObject]:
        """Declare a custom domain for one of the API stage.

        Note that when a custom domain is created then a certificate is automatically
        created for that domain.

        :param domain_name: domain name
        :param hosted_zone_id: hosted zone in which the domain belongs to
        :param stage_name: stage that should be associated with that domain
        :return: a list of AWSObject
        """
        result = []
        certificate_id = name_to_id(self.name + domain_name + "Certificate")
        certificate = Certificate(
            certificate_id,
            DomainName=domain_name,
            DomainValidationOptions=[
                DomainValidationOption(
                    DomainName=domain_name, HostedZoneId=hosted_zone_id
                )
            ],
            ValidationMethod="DNS",
        )
        result.append(certificate)
        domain = apigatewayv2.DomainName(
            name_to_id(self.name + domain_name + "Domain"),
            DomainName=domain_name,
            DomainNameConfigurations=[
                apigatewayv2.DomainNameConfiguration(CertificateArn=certificate.ref())
            ],
        )
        result.append(domain)
        result.append(
            apigatewayv2.ApiMapping(
                name_to_id(self.name + domain_name + "ApiMapping"),
                DomainName=domain.ref(),
                ApiId=self.ref,
                Stage=self.stage_ref(stage_name),
            )
        )
        result.append(
            route53.RecordSetType(
                name_to_id(self.name + domain_name + "DNS"),
                Name=domain_name,
                Type="A",
                HostedZoneId=hosted_zone_id,
                AliasTarget=route53.AliasTarget(
                    DNSName=GetAtt(
                        name_to_id(self.name + domain_name + "Domain"),
                        "RegionalDomainName",
                    ),
                    HostedZoneId=GetAtt(
                        name_to_id(self.name + domain_name + "Domain"),
                        "RegionalHostedZoneId",
                    ),
                    EvaluateTargetHealth=False,
                ),
            )
        )
        return result

    @property
    def ref(self) -> Ref:
        """Return ref to the Gateway API."""
        return Ref(name_to_id(self.name))

    def stage_ref(self, stage_name: str) -> Ref:
        """Return ref to one of the Gateway API stage.

        :param stage_name: the stage name
        """
        return Ref(name_to_id(self.name) + name_to_id(stage_name) + "Stage")

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
            "DisableExecuteApiEndpoint": self.disable_execute_api_endpoint,
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
        for route in self.route_list:
            result += self.declare_route(
                route=route, integration=Ref(logical_id + "Integration")
            )

        # Declare the domain
        if self.domain_name is not None:
            assert self.hosted_zone_id is not None
            result += self.declare_domain(
                domain_name=self.domain_name,
                hosted_zone_id=self.hosted_zone_id,
                stage_name="$default",
            )

        # Declare the authorizers
        for auth_name, auth_params in self.authorizers.items():
            result.append(apigatewayv2.Authorizer(name_to_id(auth_name), **auth_params))

        return result
