from e3.aws.cfn import AWSType, Resource


class RecordSet(Resource):
    """DNS Record."""

    def __init__(self,
                 name,
                 hosted_zone_name,
                 dns_name,
                 dns_type,
                 ttl,
                 resource_records):
        """Initialize a DNS Record.

        :param name: logical name used in the stack
        :type name: str
        :param hosted_zone_name: name of the domain for the hosted zone
        :type hosted_zone_name: str
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
        self.hosted_zone_name = hosted_zone_name
        self.dns_name = dns_name
        self.dns_type = dns_type
        self.ttl = ttl
        self.resource_records = resource_records

    @property
    def properties(self):
        return {'HostedZoneName': self.hosted_zone_name,
                'Name': self.dns_name,
                'Type': self.dns_type,
                'TTL': self.ttl,
                'ResourceRecords': self.resource_records}
