from e3.aws.cfn import AWSType, Resource
from e3.aws.cfn.ec2 import VPC


class PrivateDnsNamespace(Resource):
    def __init__(self, name, vpc, domain, description=None):
        """Initialize a private DNS namespace.

        :param name: logical name in stack
        :type name: str
        :param vpc: vpc in which the namespace is used
        :type vpc: e3.aws.ec2.VPC
        :param domain: domain
        :type domain: str
        :param description: optional description
        :type description: str | None
        """
        super(PrivateDnsNamespace, self).__init__(
            name, kind=AWSType.SERVICE_DISCOVERY_PRIVATE_DNS_NAMESPACE
        )
        self.domain = domain
        assert isinstance(vpc, VPC)
        self.vpc = vpc
        self.description = description

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {"Vpc": self.vpc.ref, "Name": self.domain}
        if self.description:
            result["Description"] = self.description
        return result
