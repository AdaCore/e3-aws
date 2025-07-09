from __future__ import annotations
from typing import TYPE_CHECKING

from e3.aws.cfn import AWSType, Resource

if TYPE_CHECKING:
    from typing import Any

    from e3.aws.cfn.ec2 import VPC


class RecordSet(Resource):
    """DNS Record."""

    def __init__(
        self,
        name: str,
        hosted_zone: HostedZone | str,
        dns_name: str,
        dns_type: str,
        ttl: int,
        resource_records: list[str],
    ) -> None:
        """Initialize a DNS Record.

        :param name: logical name used in the stack
        :param hosted_zone: name of the domain for the hosted zone
            or HostedZone object
        :param dns_name: domain name (fqdn)
        :param dns_type: record type
        :param ttl: dns TTL
        :param resource_records: list of resourses associated with the entry
        """
        super(RecordSet, self).__init__(name, kind=AWSType.ROUTE53_RECORDSET)
        self.hosted_zone = hosted_zone
        self.dns_name = dns_name
        self.dns_type = dns_type
        self.ttl = ttl
        self.resource_records = resource_records

    @property
    def properties(self) -> dict[str, Any]:
        result = {
            "Name": self.dns_name,
            "Type": self.dns_type,
            "TTL": self.ttl,
            "ResourceRecords": self.resource_records,
        }
        if isinstance(self.hosted_zone, HostedZone):
            result["HostedZoneId"] = self.hosted_zone.ref
        else:
            result["HostedZoneName"] = self.hosted_zone
        return result


class HostedZone(Resource):
    """Hosted Zone."""

    def __init__(self, name: str, domain: str, vpcs: list[VPC] | None = None) -> None:
        """Initialize an hosted zone.

        :param name: logical name in the stack
        :param domain: domain name (end it with a dot to make it absolute)
        :param vpcs: list of vpcs associated with the domain. If the list
            is empty it means that a public zone is created. Otherwise
            this is a AWS private zone.
        """
        super(HostedZone, self).__init__(name, kind=AWSType.ROUTE53_HOSTED_ZONE)
        self.domain = domain
        self.vpcs = vpcs

    @property
    def properties(self) -> dict[str, Any]:
        result: dict[str, Any] = {"Name": self.domain}
        if self.vpcs is not None:
            result["VPCs"] = [
                {"VPCId": vpc.ref, "VPCRegion": vpc.region} for vpc in self.vpcs
            ]
        return result
