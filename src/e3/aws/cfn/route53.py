from e3.aws.cfn import AWSType, Resource


class RecordSet(Resource):
    """DNS Record."""

    def __init__(self, name, hosted_zone, dns_name, dns_type, ttl, resource_records):
        """Initialize a DNS Record.

        :param name: logical name used in the stack
        :type name: str
        :param hosted_zone: name of the domain for the hosted zone
            or HostedZone object
        :type hosted_zone: str | HostedZone
        :param dns_name: domain name (fqdn)
        :type dns_name: str
        :param dns_type: record type
        :type dns_type: str
        :param ttl: dns TTL
        :type ttl: int
        :param resource_records: list of resourses associated with the entry
        :type resource_records: list[str]
        """
        super(RecordSet, self).__init__(name, kind=AWSType.ROUTE53_RECORDSET)
        self.hosted_zone = hosted_zone
        self.dns_name = dns_name
        self.dns_type = dns_type
        self.ttl = ttl
        self.resource_records = resource_records

    @property
    def properties(self):
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

    def __init__(self, name, domain, vpcs=None):
        """Initialize an hosted zone.

        :param name: logical name in the stack
        :type name: str
        :param domain: domain name (end it with a dot to make it absolute)
        :type domain: str
        :param vpcs: list of vpcs associated with the domain. If the list
            is empty it means that a public zone is created. Otherwise
            this is a AWS private zone.
        :type vpcs: None | list[VPC]
        """
        super(HostedZone, self).__init__(name, kind=AWSType.ROUTE53_HOSTED_ZONE)
        self.domain = domain
        self.vpcs = vpcs

    @property
    def properties(self):
        result = {"Name": self.domain}
        if self.vpcs is not None:
            result["VPCs"] = [
                {"VPCId": vpc.ref, "VPCRegion": vpc.region} for vpc in self.vpcs
            ]
        return result
