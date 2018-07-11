import abc

from e3.aws.cfn import AWSType, Resource
from e3.aws.cfn.ec2 import VPC


class GroupSecurityRule(object, metaclass=abc.ABCMeta):
    """Security rule for EC2 Security groups."""

    RULE_TYPE = None
    PROTOCOLS = {
        'ssh': {
            'from': 22, 'to': 22, 'protocol': 'tcp'},
        'smtps': {
            'from': 465, 'to': 465, 'protocol': 'tcp'},
        'https': {
            'from': 443, 'to': 443, 'protocol': 'tcp'},
        'http': {
            'from': 80, 'to': 80, 'protocol': 'tcp'},
        'pip': {
            'from': 3128, 'to': 3128, 'protocol': 'tcp'},
        'alltcp': {
            'from': 1, 'to': 65535, 'protocol': 'tcp'}}

    def __init__(self,
                 protocol,
                 target,
                 from_port=None,
                 to_port=None,
                 description=None):
        """Initialize a security rule.

        :param protocol: either an ip protocol name or int (see AWS
            documentation) or a protocol defined in PROTOCOLS. For the
            later port range are set automatically
        :type protocol: str | int
        :param target: correspond to destination (Egress rules) or source
            (Ingress rule). The nature of the object is determined by the
            class used. See documenation for each subclass of
            GroupSecurityRule.
        :type target: T
        :param from_port: optional starting port
        :type from_port: int | None
        :param to_port: optional ending port
        :type to_port: int | None
        :param description: optional description
        :type description: str | None
        """
        self.target = target
        if protocol in self.PROTOCOLS:
            # Handle common protocols
            p = self.PROTOCOLS[protocol]
            self.ip_protocol = p['protocol']
            self.from_port = p.get('from', None)
            self.to_port = p.get('to', None)
            self.description = p.get('description', None)
        else:
            self.ip_protocol = protocol
            self.from_port = None
            self.to_port = None
            self.description = None

        if from_port is not None:
            self.from_port = from_port

        if to_port is None:
            if self.to_port is None:
                self.to_port = self.from_port
        else:
            self.to_port = to_port

        if description is not None:
            self.description = description

    @property
    def properties(self):
        result = {self.RULE_TYPE: self.target,
                  'IpProtocol': self.ip_protocol}
        if self.from_port is not None:
            result['FromPort'] = self.from_port
        if self.to_port is not None:
            result['ToPort'] = self.to_port
        if self.description is not None:
            result['Description'] = self.description
        return result


class EgressRule(GroupSecurityRule, metaclass=abc.ABCMeta):
    pass


class IngressRule(GroupSecurityRule, metaclass=abc.ABCMeta):
    pass


class Ipv4EgressRule(EgressRule):
    RULE_TYPE = 'CidrIp'


class PrefixListEgressRule(EgressRule):
    RULE_TYPE = 'DestinationPrefixListId'


class Ipv4IngressRule(IngressRule):
    RULE_TYPE = 'CidrIp'


class SecurityGroup(Resource):
    """EC2 Security group resource."""

    def __init__(self, name, vpc, rules=None, description=None):
        """Initialize a security group.

        :param name: logical name in the stack
        :type name: str
        :param vpc: a VPC to which the rule is attached
        :type vpc: e3.aws.cfn.ec2.VPC
        :param rules: a list of rules to apply (both egress and ingress)
        :type rules: None | list[e3.aws.cfn.ec2.security.GroupSecurityRule]
        :param description: an optional description
        :type description: str | None
        """
        super(SecurityGroup, self).__init__(
            name, kind=AWSType.EC2_SECURITY_GROUP)
        assert isinstance(vpc, VPC)
        self.vpc = vpc
        self.description = description
        self.egress = []
        self.ingress = []
        if rules is not None:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule):
        """Add a rule to the security group.

        :param rule: the rule to add
        :type rule: e3.aws.cfn.ec2.security.GroupSecurityRule
        """
        if isinstance(rule, IngressRule):
            self.ingress.append(rule)
        elif isinstance(rule, EgressRule):
            self.egress.append(rule)
        else:
            assert False, "a security group rule is expected"

    @property
    def properties(self):
        result = {'VpcId': self.vpc.ref}

        if self.egress:
            result['SecurityGroupEgress'] = [r.properties for r in self.egress]
        if self.ingress:
            result['SecurityGroupIngress'] = \
                [r.properties for r in self.ingress]
        if self.description is not None:
            result['GroupDescription'] = self.description
        return result
