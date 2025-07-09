from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws.cfn import AWSType, Resource
from e3.aws.cfn.ec2 import VPC

if TYPE_CHECKING:
    from typing import Any


class PrivateDnsNamespace(Resource):
    def __init__(
        self, name: str, vpc: VPC, domain: str, description: str | None = None
    ) -> None:
        """Initialize a private DNS namespace.

        :param name: logical name in stack
        :param vpc: vpc in which the namespace is used
        :param domain: domain
        :param description: optional description
        """
        super(PrivateDnsNamespace, self).__init__(
            name, kind=AWSType.SERVICE_DISCOVERY_PRIVATE_DNS_NAMESPACE
        )
        self.domain = domain
        self.vpc = vpc
        self.description = description

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result = {"Vpc": self.vpc.ref, "Name": self.domain}
        if self.description:
            result["Description"] = self.description
        return result
