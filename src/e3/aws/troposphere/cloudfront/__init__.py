from __future__ import annotations
import os
from typing import TYPE_CHECKING, cast


from troposphere import AccountId, cloudfront, GetAtt, Join, route53, Ref, Sub

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere.awslambda import Function
from e3.aws.troposphere.iam.managed_policy import ManagedPolicy
from e3.aws.troposphere.iam.policy_statement import Allow, Trust
from e3.aws.troposphere.iam.role import Role
from e3.aws.troposphere.s3.bucket import Bucket
from e3.aws.troposphere.sns import Topic

if TYPE_CHECKING:
    from typing import Any
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack


class S3WebsiteDistribution(Construct):
    """Set a Cloudfront distribution in front of a website hosted in S3.

    It also provides a lambda invalidating cloudfront cache when s3 objects
    are updated.
    """

    def __init__(
        self,
        name: str,
        aliases: list[str],
        certificate_arn: str,
        default_ttl: int = 86400,
        bucket: Bucket | None = None,
        bucket_name: str | None = None,
        lambda_edge_function_arns: list[str] | None = None,
        root_object: str = "index.html",
        r53_route_from: list[tuple[str, str]] | None = None,
        logging_bucket: str | None = None,
        logging_prefix: str | None = None,
        logging_include_cookies: bool | None = None,
        iam_path: str | None = None,
    ):
        """Initialize a S3WebsiteCFDistribution.

        :param name: function name
        :param aliases: CNAMEs (alternate domain names), if any, for this
            distribution.
        :param certificate_arn: Amazon Resource Name (ARN) of the ACM
            certificate for aliases. Cloudfront only supports ceritificates
            stored in us-east-1.
        :param default_ttl: The default amount of time, in seconds, that you
            want objects to stay in the CloudFront cache before CloudFront sends
            another request to the origin to see if the object has been updated
        :param bucket: already existing bucket to host the website
        :param bucket_name: name of the bucket to create to host the website
        :param lambda_edge_function_arns: ARNs of Lambda@Edge functions to
            associate with the cloudfront distribution default cache behaviour
        :param root_object: The object that you want CloudFront to request from
            your origin
        :param r53_route_from: list of (hosted_zone_id, domain_id) for which to
            create route53 records
        :param logging_bucket: the Amazon S3 bucket to store the access logs in,
            for example, myawslogbucket.s3.amazonaws.com
        :param logging_prefix: an optional string that you want CloudFront to
            prefix to the access log filenames
        :param logging_include_cookies: specifies whether you want CloudFront
            to include cookies in access logs, specify true for IncludeCookies
        :param iam_path: IAM path for cloudwatch permission and role
            (must be either / or a string starting and ending with /)
        """
        assert (
            bucket is not None or bucket_name is not None
        ), "either bucket or bucket_name should be provided"
        self.name = name
        self.aliases = aliases
        # bucket_name can't be None if bucket is None
        self.bucket = Bucket(name=cast(str, bucket_name)) if bucket is None else bucket
        # If the bucket must be created by this Construct
        self._create_bucket = bucket is None
        self.certificate_arn = certificate_arn
        self.default_ttl = default_ttl
        self.lambda_edge_function_arns = lambda_edge_function_arns
        self.root_object = root_object
        self.r53_route_from = r53_route_from
        self._origin_access_identity = None
        self._cache_policy = None
        self.logging_bucket = logging_bucket
        self.logging_prefix = logging_prefix
        self.logging_include_cookies = logging_include_cookies
        self.iam_path = iam_path

    def add_oai_access_to_bucket(self) -> None:
        """Add policy granting cloudfront OAI read access to the bucket."""
        cf_principal = {
            "CanonicalUser": GetAtt(self.origin_access_identity, "S3CanonicalUserId")
        }
        self.bucket.policy_statements.extend(
            [
                Allow(
                    action="s3:GetObject",
                    resource=self.bucket.all_objects_arn,
                    principal=cf_principal,
                ),
                Allow(
                    action="s3:ListBucket",
                    resource=self.bucket.arn,
                    principal=cf_principal,
                ),
            ]
        )

    @property
    def cache_policy(self) -> cloudfront.CachePolicy:
        """Return cloudfront distribution cache policy."""
        if self._cache_policy is None:
            forwarded_to_origin = cloudfront.ParametersInCacheKeyAndForwardedToOrigin(
                CookiesConfig=cloudfront.CacheCookiesConfig(CookieBehavior="none"),
                EnableAcceptEncodingBrotli="true",
                EnableAcceptEncodingGzip="true",
                HeadersConfig=cloudfront.CacheHeadersConfig(HeaderBehavior="none"),
                QueryStringsConfig=cloudfront.CacheQueryStringsConfig(
                    QueryStringBehavior="none"
                ),
            )
            self._cache_policy = cloudfront.CachePolicy(
                name_to_id(f"{self.name}-cloudfront-cache-policy"),
                CachePolicyConfig=cloudfront.CachePolicyConfig(
                    Comment=f"{self.name} s3 website cloudfront cache policy",
                    DefaultTTL=self.default_ttl,
                    MaxTTL=31536000,
                    MinTTL=1,
                    Name="s3-cache-policy",
                    ParametersInCacheKeyAndForwardedToOrigin=forwarded_to_origin,
                ),
            )
        return self._cache_policy

    @property
    def distribution(self) -> cloudfront.Distribution:
        """Return cloudfront distribution with bucket as origin."""
        origin = cloudfront.Origin(
            S3OriginConfig=cloudfront.S3OriginConfig(
                OriginAccessIdentity=Join(
                    "",
                    [
                        "origin-access-identity/cloudfront/",
                        Ref(self.origin_access_identity),
                    ],
                )
            ),
            DomainName=f"{self.bucket.name}.s3.amazonaws.com",
            Id="S3Origin",
        )
        cache_params = {
            "AllowedMethods": ["GET", "HEAD", "OPTIONS"],
            "CachePolicyId": Ref(self.cache_policy),
            "TargetOriginId": "S3Origin",
            "ViewerProtocolPolicy": "redirect-to-https",
        }
        if self.lambda_edge_function_arns:
            cache_params["LambdaFunctionAssociations"] = [
                cloudfront.LambdaFunctionAssociation(
                    EventType="viewer-request", LambdaFunctionARN=lambda_arn
                )
                for lambda_arn in self.lambda_edge_function_arns
            ]

        default_cache_behavior = cloudfront.DefaultCacheBehavior(**cache_params)

        params: dict[str, Any] = {}
        if self.logging_bucket is not None:
            params["Logging"] = cloudfront.Logging(
                Bucket=self.logging_bucket,
                Prefix=self.logging_prefix if self.logging_prefix is not None else "",
                IncludeCookies=self.logging_include_cookies
                if self.logging_include_cookies is not None
                else False,
            )

        return cloudfront.Distribution(
            name_to_id(self.name),
            DistributionConfig=cloudfront.DistributionConfig(
                Aliases=self.aliases,
                DefaultRootObject=self.root_object,
                DefaultCacheBehavior=default_cache_behavior,
                Enabled="True",
                HttpVersion="http2",
                Origins=[origin],
                ViewerCertificate=cloudfront.ViewerCertificate(
                    AcmCertificateArn=self.certificate_arn,
                    SslSupportMethod="sni-only",
                    MinimumProtocolVersion="TLSv1.2_2021",
                ),
                **params,
            ),
        )

    @property
    def origin_access_identity(self) -> cloudfront.CloudFrontOriginAccessIdentity:
        """Return cloudformation access identity.

        It is needed to be used as principal for s3 bucket access policy.
        """
        if self._origin_access_identity is None:
            cf_oai_config = cloudfront.CloudFrontOriginAccessIdentityConfig(
                Comment=f"{self.name} Cloudfront origin access identity"
            )
            self._origin_access_identity = cloudfront.CloudFrontOriginAccessIdentity(
                name_to_id(f"{self.name}-cloudfront-oai"),
                CloudFrontOriginAccessIdentityConfig=cf_oai_config,
            )
        return self._origin_access_identity

    def add_cache_invalidation(self, stack: Stack) -> list[AWSObject]:
        """Return resources invalidating cache when objects are pushed to s3.

        A lambda is called at each s3 object update to invalidate cloudformation
        cache for the updated object.
        """
        iam_path = f"/{stack.name}/" if self.iam_path is None else self.iam_path

        lambda_name = f"{self.name}-cache-invalidation-lambda"
        lambda_policy = ManagedPolicy(
            name=f"{lambda_name}-policy",
            description=f"managed policy used by {lambda_name}",
            path=iam_path,
            statements=[
                Allow(
                    action=["cloudfront:CreateInvalidation"],
                    resource=Join(
                        "",
                        ["arn:aws:cloudfront::", AccountId, ":distribution ", self.id],
                    ),
                )
            ],
        )
        lambda_role = Role(
            name=f"{lambda_name}-role",
            description=f"role assumed by {lambda_name}",
            path=iam_path,
            trust=Trust(services=["lambda"]),
            managed_policy_arns=[lambda_policy.arn],
        )

        # Get first part of invalidation lambda code from a file
        with open(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "data",
                "lambda_invalidate_head.py",
            )
        ) as lf:
            lambda_code = lf.read().splitlines()

        # Complete it with the part depending on the distribution id
        lambda_code.extend(
            [
                "    client.create_invalidation(",
                Sub(
                    "        DistributionId='${distribution_id}',",
                    distribution_id=self.id,
                ),
                "        InvalidationBatch={",
                "            'Paths': {'Quantity': 1, 'Items': path},",
                "            'CallerReference': str(time.time()),",
                "        },",
                "    )",
            ]
        )
        lambda_function = Function(
            name_to_id(lambda_name),
            description=(
                f"lambda invalidating cloudfront cache when "
                f"{self.bucket.name} objects are updated"
            ),
            handler="invalidate.handler",
            role=lambda_role,
            code_zipfile=Join("\n", lambda_code),
            runtime="python3.9",
        )

        sns_topic = Topic(name=f"{self.name}-invalidation-topic")
        sns_topic.add_lambda_subscription(
            function=lambda_function,
            delivery_policy={"throttlePolicy": {"maxReceivesPerSecond": 10}},
        )
        # Trigger the invalidation when a file is updated
        self.bucket.add_notification_configuration(
            event="s3:ObjectCreated:*", target=sns_topic, permission_suffix=self.name
        )

        result = [
            resource
            for construct in (lambda_policy, lambda_role, lambda_function, sns_topic)
            for resource in construct.resources(stack)
        ]
        return result

    @property
    def domain_name(self) -> GetAtt:
        """Return cloudfront distribution domain name."""
        return GetAtt(name_to_id(self.name), "DomainName")

    @property
    def id(self) -> Ref:
        """Return cloudfront distribution id."""
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        # Add bucket policy granting read access to te cloudfront distribution
        self.add_oai_access_to_bucket()

        result = [
            *(self.bucket.resources(stack) if self._create_bucket else []),
            self.cache_policy,
            self.distribution,
            self.origin_access_identity,
        ]

        # Add a lambda invalidating cloudfront cache when bucket objects are modified
        result.extend(self.add_cache_invalidation(stack))

        # Add route53 records if needed
        if self.r53_route_from:
            for zone_id, domain in self.r53_route_from:
                result.append(
                    route53.RecordSetType(
                        name_to_id(f"{self.name}-{domain}-r53-rset"),
                        AliasTarget=route53.AliasTarget(
                            DNSName=self.domain_name,
                            # Z2FDTNDATAQYW2 is always the hosted zone ID when you
                            # create an alias record that routes traffic to a
                            # CloudFront distribution
                            HostedZoneId="Z2FDTNDATAQYW2",
                        ),
                        Name=domain,
                        HostedZoneId=zone_id,
                        Type="A",
                    )
                )
        return result
