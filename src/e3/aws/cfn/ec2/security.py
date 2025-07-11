from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws.cfn import AWSType, GetAtt, Resource
from e3.aws.cfn.ec2 import VPC

if TYPE_CHECKING:
    from typing import Any


class GroupSecurityRule:
    """Security rule for EC2 Security groups."""

    RULE_TYPE: str | None = None
    PROTOCOLS: dict[str | int, dict[str, int | str]] = {
        "ssh": {"from": 22, "to": 22, "protocol": "tcp"},
        "smtps": {"from": 465, "to": 465, "protocol": "tcp"},
        "https": {"from": 443, "to": 443, "protocol": "tcp"},
        "http": {"from": 80, "to": 80, "protocol": "tcp"},
        "pip": {"from": 3128, "to": 3128, "protocol": "tcp"},
        "alltcp": {"from": 1, "to": 65535, "protocol": "tcp"},
        "ntp": {"from": 123, "to": 123, "protocol": "udp"},
        "postgresql": {"from": 5432, "to": 5432, "protocol": "tcp"},
    }

    def __init__(
        self,
        protocol: str | int,
        target: Any,
        from_port: int | None = None,
        to_port: int | None = None,
        description: str | None = None,
    ):
        """Initialize a security rule.

        :param protocol: either an ip protocol name or int (see AWS
            documentation) or a protocol defined in PROTOCOLS. For the
            later port range are set automatically
        :param target: correspond to destination (Egress rules) or source
            (Ingress rule). The nature of the object is determined by the
            class used. See documenation for each subclass of
            GroupSecurityRule.
        :param from_port: optional starting port
        :param to_port: optional ending port
        :param description: optional description
        """
        self.target = target
        if protocol in self.PROTOCOLS:
            # Handle common protocols
            p = self.PROTOCOLS[protocol]
            self.ip_protocol = p["protocol"]
            self.from_port = p.get("from", None)
            self.to_port = p.get("to", None)
            self.description = p.get("description", None)
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
    def properties(self) -> dict[str, Any]:
        result: dict[str, Any] = {"IpProtocol": self.ip_protocol}
        if self.RULE_TYPE is not None:
            result[self.RULE_TYPE] = self.target
        if self.from_port is not None:
            result["FromPort"] = self.from_port
        if self.to_port is not None:
            result["ToPort"] = self.to_port
        if self.description is not None:
            result["Description"] = self.description
        return result


class EgressRule(GroupSecurityRule):
    pass


class IngressRule(GroupSecurityRule):
    pass


class Ipv4EgressRule(EgressRule):
    RULE_TYPE: str = "CidrIp"


class PrefixListEgressRule(EgressRule):
    RULE_TYPE: str = "DestinationPrefixListId"


class Ipv4IngressRule(IngressRule):
    RULE_TYPE: str = "CidrIp"


class SecurityGroup(Resource):
    """EC2 Security group resource."""

    def __init__(
        self,
        name: str,
        vpc: VPC,
        rules: list[GroupSecurityRule] | None = None,
        description: str | None = None,
    ) -> None:
        """Initialize a security group.

        :param name: logical name in the stack
        :param vpc: a VPC to which the rule is attached
        :param rules: a list of rules to apply (both egress and ingress)
        :param description: an optional description
        """
        super().__init__(name, kind=AWSType.EC2_SECURITY_GROUP)
        self.vpc = vpc
        self.description = description
        self.egress: list[EgressRule] = []
        self.ingress: list[IngressRule] = []
        if rules is not None:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule: GroupSecurityRule) -> None:
        """Add a rule to the security group.

        :param rule: the rule to add
        """
        if isinstance(rule, IngressRule):
            self.ingress.append(rule)
        elif isinstance(rule, EgressRule):
            self.egress.append(rule)
        else:
            raise AssertionError("a security group rule is expected")

    @property
    def group_id(self) -> GetAtt:
        """Return SecurityGroup GroupId."""
        return GetAtt(self.name, "GroupId")

    @property
    def properties(self) -> dict[str, Any]:
        result: dict[str, Any] = {"VpcId": self.vpc.ref}

        if self.egress:
            result["SecurityGroupEgress"] = [r.properties for r in self.egress]
        if self.ingress:
            result["SecurityGroupIngress"] = [r.properties for r in self.ingress]
        if self.description is not None:
            result["GroupDescription"] = self.description
        return result
