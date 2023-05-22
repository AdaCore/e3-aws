from __future__ import annotations
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING
from abc import abstractmethod
from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from troposphere import (
    apigatewayv2,
    route53,
    Ref,
    logs,
    GetAtt,
    awslambda,
    Sub,
    apigateway,
)
from troposphere.apigateway import BasePathMapping
from troposphere.apigatewayv2 import ApiMapping
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from e3.aws.troposphere.iam.policy_statement import PolicyStatement, Trust
from e3.aws.troposphere.iam.role import Role
from troposphere import AWSObject
from troposphere.certificatemanager import Certificate, DomainValidationOption
import json
import re

if TYPE_CHECKING:
    from e3.aws.troposphere import Stack
    from typing import Any, TypedDict, Literal

    # Possible HTTP methods.
    HttpMethod = Literal[
        "GET", "POST", "PUT", "DELETE", "ANY", "HEAD", "OPTIONS", "PATCH"
    ]


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


class Method:
    """API Gateway method definition."""

    def __init__(
        self,
        method: HttpMethod,
        auth: AuthorizationType | None = None,
        authorizer_name: str | None = None,
    ) -> None:
        """Initialize an API Gateway method definition.

        :param method: the https method
        :param auth: the authorization type associated with the method
        :param authorizer_name: the name of the authorizer to use
            (used only when using JWT_AUTH)
        """
        self.method = method
        self.auth = auth if auth is not None else NO_AUTH
        self.authorizer_name = authorizer_name


class Route(Method):
    """API Gateway route definition."""

    def __init__(
        self,
        method: HttpMethod,
        route: str,
        auth: AuthorizationType = NO_AUTH,
        authorizer_name: str | None = None,
    ) -> None:
        """Initialize an API Gateway route definition.

        :param method: the https method
        :param route: the route (should start with a "/")
        :param auth: the authorization type associated with the route
        :param authorizer_name: the name of the authorizer to use
            (used only when using JWT_AUTH)
        """
        assert route.startswith("/"), "route path should starts with a /"
        self.route = route
        super().__init__(method=method, auth=auth, authorizer_name=authorizer_name)


class GET(Route):
    """An API Gateway GET route."""

    def __init__(
        self,
        route: str,
        auth: AuthorizationType = NO_AUTH,
        authorizer_name: str | None = None,
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
        authorizer_name: str | None = None,
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


class StageConfiguration(object):
    """HTTP API stage configuration."""

    def __init__(
        self,
        name: str,
        api_mapping_key: str | None = None,
        lambda_arn_permission: str | GetAtt | Ref | None = None,
        variables: dict[str, str] | None = None,
    ) -> None:
        """Create a stage configuration.

        :param name: name of the stage (use $default for the default stage)
        :param api_mapping_key: the API mapping key (only used when creating an HTTP API
            with a domain name and hosted zone id)
        :param lambda_arn_permission: lambda arn for which to add InvokeFunction
            permission for this stage (can be different from the lambda arn executed
            by the HTTP API)
        :param variables: a map that defines the stage variables
        """
        self.name = name
        self.api_mapping_key = api_mapping_key
        self.lambda_arn_permission = lambda_arn_permission
        self.variables = variables


class Api(Construct):
    """API abstact Class for APIGateways V1 and V2."""

    if TYPE_CHECKING:

        class _AliasTargetAttributes(TypedDict):
            DNSName: str
            HostedZoneId: str

    def __init__(
        self,
        name: str,
        description: str,
        lambda_arn: str | GetAtt | Ref,
        burst_limit: int = 10,
        rate_limit: int = 10,
        domain_name: str | None = None,
        hosted_zone_id: str | None = None,
        stages_config: list[StageConfiguration] | None = None,
    ):
        """Initialize API resource.

        :param name: the resource name
        :param description: the resource description
        :param lambda_arn: arn of the lambda executed for all routes
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
        :param stages_config: configurations of the different stages
        :param integration_uri: URI of a Lambda function
        """
        self.name = name
        self.description = description
        self.lambda_arn = lambda_arn
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
        # By default, make sure to have a $default stage
        self.stages_config = (
            stages_config if stages_config else [StageConfiguration("$default")]
        )

    @cached_property
    def logical_id(self) -> str:
        """Get the API's logical ID."""
        return name_to_id(self.name)

    def stage_logical_id(self, stage_name: str) -> str:
        """Get the name of the Stage resource.

        :param stage_name: the stage name
        """
        return self.logical_id + name_to_id(stage_name) + "Stage"

    @cached_property
    def log_group_id(self) -> str:
        """Get logGroup's id."""
        return self.logical_id + "LogGroup"

    @cached_property
    def ref(self) -> Ref:
        """Return ref to the Gateway API."""
        return Ref(self.logical_id)

    def stage_ref(self, stage_name: str) -> Ref:
        """Return ref to one of the Gateway API stage.

        :param stage_name: the stage name
        """
        return Ref(self.stage_logical_id(stage_name))

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

    @abstractmethod
    def declare_stage(
        self,
        stage_name: str,
        log_arn: str | GetAtt,
        *,
        stage_variables: dict[str, str] | None = None,
    ) -> apigatewayv2.Stage | list[AWSObject]:
        """Declare an API gateway stage.

        :param stage_name: name of the stage
        :param log_arn: arn of the cloudwatch log group in which api calls
            should be logged
        :param stage_variables: variables for the different stages
        :return: the AWSObject corresponding to the Stage
        """
        pass

    def _declare_certificate(
        self, domain_name: str, hosted_zone_id: str
    ) -> Certificate:
        """Declare the API's domain certificate.

        :param domain_name: domain name
        :param hosted_zone_id: hosted zone in which the domain belongs to
        :return: domain name certificate
        """
        return Certificate(
            name_to_id(self.name + domain_name + "Certificate"),
            DomainName=domain_name,
            DomainValidationOptions=[
                DomainValidationOption(
                    DomainName=domain_name, HostedZoneId=hosted_zone_id
                )
            ],
            ValidationMethod="DNS",
        )

    @abstractmethod
    def _declare_domain_name(
        self, domain_name: str, certificate_arn: Ref | str
    ) -> apigatewayv2.DomainName | apigateway.DomainName:
        """Declare the domain name aws resource of the API.

        :param domain_name: domain name
        :param certificate_arn: the ARN of the certificate
        :return: the domain name aws resource
        """
        pass

    @abstractmethod
    def _declare_api_mapping(
        self, domain_name: apigatewayv2.DomainName | apigateway.DomainName
    ) -> list[BasePathMapping | ApiMapping]:
        """Declare the API's mapping.

        :param domain_name: the custom domain name for the API
        return: a list api mapping aws object
        """
        pass

    @abstractmethod
    def _get_alias_target_attributes(self) -> Api._AliasTargetAttributes:
        """Get atributes to pass to GetAtt for alias target."""
        pass

    def declare_domain(self, domain_name: str, hosted_zone_id: str) -> list[AWSObject]:
        """Declare a custom domain for the API stages.

        Note that when a custom domain is created then a certificate is automatically
        created for that domain.

        :param domain_name: domain name
        :param hosted_zone_id: hosted zone in which the domain belongs to
        :return: a list of AWSObject
        """
        result = []

        certificate = self._declare_certificate(
            domain_name=domain_name, hosted_zone_id=hosted_zone_id
        )
        result.append(certificate)

        domain = self._declare_domain_name(
            domain_name=domain_name,
            certificate_arn=certificate.ref(),
        )
        result.append(domain)

        result += self._declare_api_mapping(domain)
        alias_target = self._get_alias_target_attributes()

        result.append(
            route53.RecordSetType(
                name_to_id(self.name + domain_name + "DNS"),
                Name=domain_name,
                Type="A",
                HostedZoneId=hosted_zone_id,
                AliasTarget=route53.AliasTarget(
                    DNSName=GetAtt(
                        domain.title,
                        alias_target["DNSName"],
                    ),
                    HostedZoneId=GetAtt(
                        domain.title,
                        alias_target["HostedZoneId"],
                    ),
                    EvaluateTargetHealth=False,
                ),
            )
        )
        return result


class HttpApi(Api):
    """HTTP API support."""

    def __init__(
        self,
        name: str,
        description: str,
        lambda_arn: str | GetAtt | Ref,
        route_list: list[Route],
        burst_limit: int = 10,
        rate_limit: int = 10,
        domain_name: str | None = None,
        hosted_zone_id: str | None = None,
        stages_config: list[StageConfiguration] | None = None,
        integration_uri: str | Ref | Sub | None = None,
    ):
        """Initialize an HTTP API.

        The schema supported here is a single lambda handling all the routes.
        Nevertherless, we don't use {proxy}+ route and rather declare
        statically the list of supported route. This ensure that our lambda is
        not executed whenever an invalid route is invoked. Thus the cost of invoking
        an invalid route is 0.

        The API can use one stage ($default) or multiple stages with stages_config.

        :param name: the resource name
        :param description: the resource description
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
        :param stages_config: configurations of the different stages
        :param integration_uri: URI of a Lambda function
        """
        super().__init__(
            name=name,
            description=description,
            lambda_arn=lambda_arn,
            burst_limit=burst_limit,
            rate_limit=rate_limit,
            domain_name=domain_name,
            hosted_zone_id=hosted_zone_id,
            stages_config=stages_config,
        )
        self.route_list = route_list
        self.integration_uri = (
            integration_uri if integration_uri is not None else lambda_arn
        )

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

    def declare_stage(
        self,
        stage_name: str,
        log_arn: str | GetAtt,
        *,
        stage_variables: dict[str, str] | None = None,
    ) -> apigatewayv2.Stage:
        """Declare an API gateway stage.

        :param stage_name: name of the stage
        :param log_arn: arn of the cloudwatch log group in which api calls
            should be logged
        :param stage_variables: variables for the different stages
        :return: the AWSObject corresponding to the Stage
        """
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
            DestinationArn=GetAtt(self.log_group_id, "Arn"),
            Format=json.dumps(log_format),
        )

        route_settings = apigatewayv2.RouteSettings(
            DetailedMetricsEnabled=True,
            ThrottlingBurstLimit=self.burst_limit,
            ThrottlingRateLimit=self.rate_limit,
        )

        parameters: dict[str, Any] = {}

        if stage_variables is not None:
            parameters["StageVariables"] = stage_variables

        return apigatewayv2.Stage(
            self.stage_logical_id(stage_name),
            AccessLogSettings=access_log_settings,
            ApiId=Ref(self.logical_id),
            AutoDeploy=True,
            Description=f"stage {stage_name}",
            DefaultRouteSettings=route_settings,
            StageName=stage_name,
            **parameters,
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

        for config in self.stages_config:
            result.append(
                awslambda.Permission(
                    # Retain old behavior for the $default stage
                    name_to_id(
                        "{}-{}LambdaPermission".format(
                            id_prefix, "" if config.name == "$default" else config.name
                        )
                    ),
                    Action="lambda:InvokeFunction",
                    FunctionName=config.lambda_arn_permission
                    if config.lambda_arn_permission is not None
                    else self.lambda_arn,
                    Principal="apigateway.amazonaws.com",
                    SourceArn=Sub(
                        "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                        f"${{api}}/{config.name}/${{route_arn}}",
                        dict_values={
                            "api": self.ref,
                            "route_arn": f"{route.method}{route.route}",
                        },
                    ),
                )
            )
        return result

    def _declare_domain_name(
        self, domain_name: str, certificate_arn: Ref | str
    ) -> apigatewayv2.DomainName | apigateway.DomainName:
        """Declare the domain name aws resource of the API.

        :param domain_name: domain name
        :param certificate_arn: the ARN of the certificate
        :return: a domain name aws resource
        """
        return apigatewayv2.DomainName(
            name_to_id(self.name + domain_name + "Domain"),
            DomainName=domain_name,
            DomainNameConfigurations=[
                apigatewayv2.DomainNameConfiguration(CertificateArn=certificate_arn)
            ],
        )

    def _declare_api_mapping(
        self, domain_name: apigatewayv2.DomainName | apigateway.DomainName
    ) -> list[BasePathMapping | ApiMapping]:
        """Declare the API's mapping.

        :param domain_name: the custom domain name for the API
        return: a list api mapping aws object
        """
        result = []
        for config in self.stages_config:
            mapping_params = {
                "DomainName": domain_name.ref(),
                "Stage": self.stage_ref(config.name),
                "ApiId": self.ref,
            }

            if config.api_mapping_key is not None:
                mapping_params["ApiMappingKey"] = config.api_mapping_key
            result.append(
                apigatewayv2.ApiMapping(
                    # Retain old behavior for the $default stage
                    name_to_id(
                        "{}{}-{}ApiMapping".format(
                            self.name,
                            domain_name.DomainName,
                            "" if config.name == "$default" else config.name,
                        )
                    ),
                    **mapping_params,
                )
            )
        return result

    def _get_alias_target_attributes(self) -> Api._AliasTargetAttributes:
        """Get atributes to pass to GetAtt for alias target."""
        return {
            "DNSName": "RegionalDomainName",
            "HostedZoneId": "RegionalHostedZoneId",
        }

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        result = []

        # Create a log group for the API
        result.append(logs.LogGroup(self.log_group_id, LogGroupName=self.name))

        # Create the API itself
        api_params = {
            "Description": self.description,
            "ProtocolType": "HTTP",
            "Name": self.name,
            "DisableExecuteApiEndpoint": self.disable_execute_api_endpoint,
        }
        result.append(apigatewayv2.Api(self.logical_id, **api_params))

        # Declare the different stages
        for config in self.stages_config:
            result.append(
                self.declare_stage(
                    stage_name=config.name,
                    log_arn=GetAtt(self.log_group_id, "Arn"),
                    stage_variables=config.variables,
                )
            )

        # Declare one integration
        result.append(
            apigatewayv2.Integration(
                self.logical_id + "Integration",
                ApiId=self.ref,
                IntegrationType="AWS_PROXY",
                IntegrationUri=self.integration_uri,
                PayloadFormatVersion="2.0",
            )
        )

        # Declare the routes
        for route in self.route_list:
            result += self.declare_route(
                route=route, integration=Ref(self.logical_id + "Integration")
            )

        # Declare the domain
        if self.domain_name is not None:
            assert self.hosted_zone_id is not None
            result += self.declare_domain(
                domain_name=self.domain_name, hosted_zone_id=self.hosted_zone_id
            )

        # Declare the authorizers
        for auth_name, auth_params in self.authorizers.items():
            result.append(apigatewayv2.Authorizer(name_to_id(auth_name), **auth_params))

        return result


class RestApi(Api):
    """Rest API support."""

    def __init__(
        self,
        name: str,
        description: str,
        lambda_arn: str | GetAtt | Ref,
        method_list: list[Method],
        burst_limit: int = 10,
        rate_limit: int = 10,
        domain_name: str | None = None,
        hosted_zone_id: str | None = None,
        stages_config: list[StageConfiguration] | None = None,
        integration_uri: str | Ref | Sub | None = None,
        iam_path: str = "/",
        policy: list[PolicyStatement] | None = None,
    ):
        """Initialize a Rest API.

        The schema supported here is a single lambda handling the API.
        To limit lambda invocation costs we can add a policy that restricts
        invocation.

        The API can use either only one stage ($default) or multiple.

        For the moment the RestApi construct has a bug: the base URL
        does not work properly and returns an error message when used
        even if a "/" route is set in the lambda. For example, if we
        set as the domain name of the REST API example.com, trying to
        use or access  the URL example.com returns the following error
        message:  '{"message":"Missing Authentication Token"}' even if
        an authentication method has not been set. However, using other
        routes should work fine e.g. example.com/hello. So for the moment
        using the default(/) in the lambda should be avoided.

        :param name: the resource name
        :param lambda_arn: arn of the lambda executed for all routes
        :param method_list: a list of methods to declare
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
        :param stages_config: configurations of the different stages
        :param integration_uri: URI of a Lambda function
        :param iam_path: IAM path for cloudwatch permission and role
            (must be either / or a string starting and ending with /)
        :param policy: the policy document that contains the permissions for
            the RestApi resource.
        """
        super().__init__(
            name=name,
            description=description,
            lambda_arn=lambda_arn,
            burst_limit=burst_limit,
            rate_limit=rate_limit,
            domain_name=domain_name,
            hosted_zone_id=hosted_zone_id,
            stages_config=stages_config,
        )
        self.method_list = method_list
        self.integration_uri = (
            integration_uri
            if integration_uri is not None
            else Sub(
                "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31"
                "/functions/${lambdaArn}/invocations",
                dict_values={"lambdaArn": lambda_arn},
            )
        )
        assert iam_path.startswith("/"), "iam_path must start with '/'"
        assert iam_path.endswith("/"), "iam_path must end with '/'"
        self.iam_path = iam_path
        self.policy = policy

    def add_cognito_authorizer(
        # we ignore the incompatible signature mypy errors
        self,
        name: str,
        providers_arn: list[str],
        header: str = "Authorization",
    ) -> None:
        """Declare a JWT authorizer.

        :param name: authorizer name
        :param providers_arn: a  list of the Cognito user pool ARNs for the
            COGNITO_USER_POOLS authorizer.Each element is of this format:
            arn:aws:cognito-idp:{region}:{account_id}:userpool/{user_pool_id}.
        :param header: the request header holding the authorization token
            submitted by the client
        """
        self.authorizers[name] = {
            "IdentitySource": f"method.request.header.{header}",
            "Name": name,
            "ProviderARNs": providers_arn,
            "RestApiId": self.ref,
            "Type": "COGNITO_USER_POOLS",
        }

    def declare_stage(
        self,
        stage_name: str,
        log_arn: str | GetAtt,
        *,
        stage_variables: dict[str, str] | None = None,
    ) -> list[AWSObject]:
        """Declare an API gateway stage.

        :param stage_name: name of the stage
        :param log_arn: arn of the cloudwatch log group in which api calls
            should be logged
        :param stage_variables: variables for the different stages
        :return: Stage and Deployment AWSObjects
        """
        result = []

        # create deployment resource
        deployment_name = self.logical_id + name_to_id(stage_name) + "Deployment"
        result.append(
            apigateway.Deployment(
                deployment_name,
                Description=f"Deployment resource of {stage_name} stage",
                RestApiId=Ref(self.logical_id),
                DependsOn=[
                    name_to_id(self.name + method.method + "Method")
                    for method in self.method_list
                ],
            )
        )

        # create stage resource

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

        access_log_settings = apigateway.AccessLogSetting(
            DestinationArn=GetAtt(self.log_group_id, "Arn"),
            Format=json.dumps(log_format),
        )

        method_settings = apigateway.MethodSetting(
            ResourcePath="/*",
            HttpMethod="*",
            MetricsEnabled=True,
            ThrottlingBurstLimit=self.burst_limit,
            ThrottlingRateLimit=self.rate_limit,
        )

        parameters: dict[str, Any] = {}

        if stage_variables is not None:
            parameters["Variables"] = stage_variables

        result.append(
            apigateway.Stage(
                self.stage_logical_id(stage_name=stage_name),
                AccessLogSetting=access_log_settings,
                RestApiId=Ref(self.logical_id),
                DeploymentId=Ref(deployment_name),
                Description=f"stage {stage_name}",
                MethodSettings=[method_settings],
                # Stage name only allows a-zA-Z0-9_
                StageName=re.sub("[^a-zA-Z0-9_]", "", stage_name),
                **parameters,
            )
        )

        return result

    def declare_method(self, method: Method, resource_id: Ref) -> list[AWSObject]:
        """Declare a method.

        :param method: the method definition
        :return: a list of AWSObjects to be added to the stack
        """
        result = []
        id_prefix = name_to_id(self.name + method.method)

        integration = apigateway.Integration(
            id_prefix + "Integration",
            # set at POST because we are doing lambda integration
            CacheKeyParameters=[],
            CacheNamespace="none",
            IntegrationHttpMethod="POST",
            PassthroughBehavior="NEVER",
            Type="AWS_PROXY",
            Uri=self.integration_uri,
        )

        method_params = {
            "RestApiId": self.ref,
            "AuthorizationType": "COGNITO_USER_POOLS"
            if method.authorizer_name
            else "NONE",
            "HttpMethod": f"{method.method}",
            "Integration": integration,
            "ResourceId": resource_id,
        }
        if method.authorizer_name:
            method_params["AuthorizerId"] = Ref(name_to_id(method.authorizer_name))

        result.append(apigateway.Method(id_prefix + "Method", **method_params))

        for config in self.stages_config:
            result.append(
                awslambda.Permission(
                    # Retain old behavior for the $default stage
                    name_to_id(
                        "{}-{}LambdaPermission".format(
                            id_prefix, "" if config.name == "$default" else config.name
                        )
                    ),
                    Action="lambda:InvokeFunction",
                    FunctionName=self.lambda_arn,
                    Principal="apigateway.amazonaws.com",
                    SourceArn=Sub(
                        "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:"
                        f"${{api}}/{config.name}/${{method}}/*",
                        dict_values={
                            "api": self.ref,
                            "method": method.method,
                        },
                    ),
                )
            )
        return result

    def _declare_domain_name(
        self, domain_name: str, certificate_arn: Ref | str
    ) -> apigatewayv2.DomainName | apigateway.DomainName:
        """Declare the domain name aws resource of the API.

        :param domain_name: domain name
        :param certificate_arn: the ARN of the certificate
        :return: a domain name aws resource
        """
        return apigateway.DomainName(
            name_to_id(self.name + domain_name + "Domain"),
            DomainName=domain_name,
            CertificateArn=certificate_arn,
        )

    def _declare_api_mapping(
        self, domain_name: apigatewayv2.DomainName | apigateway.DomainName
    ) -> list[BasePathMapping | ApiMapping]:
        """Declare the API's mapping.

        :param domain_name: the custom domain name for the API
        return: a list api mapping aws object
        """
        result = []
        for config in self.stages_config:
            mapping_params = {
                "DomainName": domain_name.ref(),
                "Stage": self.stage_ref(config.name),
                "RestApiId": self.ref,
            }

            if config.api_mapping_key is not None:
                mapping_params["BasePath"] = config.api_mapping_key
            result.append(
                apigateway.BasePathMapping(
                    # Retain old behavior for the $default stage
                    name_to_id(
                        "{}{}-{}BasePathMapping".format(
                            self.name,
                            domain_name.DomainName,
                            "" if config.name == "$default" else config.name,
                        )
                    ),
                    **mapping_params,
                )
            )
        return result

    def _get_alias_target_attributes(self) -> Api._AliasTargetAttributes:
        """Get atributes to pass to GetAtt for alias target."""
        return {
            "DNSName": "DistributionDomainName",
            "HostedZoneId": "DistributionHostedZoneId",
        }

    def declare_access_cloudwatch_resources(self) -> list[AWSObject]:
        """Create role and account resources to enable CloudWatch Logs.

        Specify the IAM role that Amazon API Gateway should use to write API
        logs to Amazon CloudWatch.These resources must be created at least
        once per account per region for the class RestApi to be able to be
        deployed.

        :return: a role and an account cloudformation objects
        """
        result: list[AWSObject] = []

        access_cloudwatch_role = Role(
            name="EnableCloudwatchLoggingForApigatewayRole",
            description="role that enables CloudWatch logging for apigateway v1"
            " apigateway",
            trust=Trust(services=["apigateway"]),
            managed_policy_arns=[
                # we use the AmazonAPIGatewayPushToCloudWatchLogs managed policy
                # that has all the required permissions
                Sub(
                    "arn:${AWS::Partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
                )
            ],
            path=self.iam_path,
        )

        result.append(access_cloudwatch_role)
        result.append(
            apigateway.Account(
                self.logical_id + "Account",
                CloudWatchRoleArn=access_cloudwatch_role.arn,
            )
        )

        return result

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        result = []

        # Create a log group for the API
        result.append(logs.LogGroup(self.log_group_id, LogGroupName=self.name))

        # Create the API itself
        api_params = {
            "Description": self.description,
            "Name": self.name,
            "DisableExecuteApiEndpoint": self.disable_execute_api_endpoint,
        }
        if self.policy:
            api_params["Policy"] = PolicyDocument(statements=self.policy).as_dict

        result.append(apigateway.RestApi(self.logical_id, **api_params))

        # Create an API resource
        resource_name = self.logical_id + "Resource"
        result.append(
            apigateway.Resource(
                resource_name,
                ParentId=GetAtt(self.logical_id, "RootResourceId"),
                RestApiId=self.ref,
                PathPart="{proxy+}",
            )
        )

        # Declare the different stages
        for config in self.stages_config:
            result.extend(
                self.declare_stage(
                    stage_name=config.name,
                    log_arn=GetAtt(self.log_group_id, "Arn"),
                    stage_variables=config.variables,
                )
            )

        # Declare the methods
        for method in self.method_list:
            result += self.declare_method(method=method, resource_id=Ref(resource_name))

        # Declare the domain
        if self.domain_name is not None:
            assert self.hosted_zone_id is not None
            result += self.declare_domain(
                domain_name=self.domain_name, hosted_zone_id=self.hosted_zone_id
            )

        # Declare the authorizers
        for auth_name, auth_params in self.authorizers.items():
            result.append(apigateway.Authorizer(name_to_id(auth_name), **auth_params))

        return result
