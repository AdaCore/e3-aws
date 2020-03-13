import requests
from e3.aws.cfn.ec2.security import Ipv4EgressRule, SecurityGroup

# This is the static address at which AWS publish the list of ip-ranges
# used by its services.
IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def amazon_security_group(name, vpc):
    """Create a security group authorizing access to aws services.

    :param vpc: vpc in which to create the group
    :type vpc: VPC
    :return: a security group
    :rtype: SecurityGroup
    """
    ip_ranges = requests.get(IP_RANGES_URL).json()["prefixes"]

    # Retrieve first the complete list of ipv4 ip ranges for a given region
    amazon_ip_ranges = {
        k["ip_prefix"]
        for k in ip_ranges
        if k["region"] == vpc.region and "ip_prefix" in k and k["service"] == "AMAZON"
    }

    # Sustract the list of ip ranges corresponding to EC2 instances
    ec2_ip_ranges = {
        k["ip_prefix"]
        for k in ip_ranges
        if k["region"] == vpc.region and "ip_prefix" in k and k["service"] == "EC2"
    }
    amazon_ip_ranges -= ec2_ip_ranges

    # Authorize https on the resulting list of ip ranges
    # Note: the limit of rules per security group is set to 50 at AWS.
    # In case the number of ip ranges returned by Amazon would be greater
    # than that there would be need to split into several security groups
    sg = SecurityGroup(name, vpc, description="Allow acces to amazon services")
    for ip_range in amazon_ip_ranges:
        sg.add_rule(Ipv4EgressRule("https", ip_range))

    return sg


def amazon_security_groups(name, vpc):
    """Create a dict of security group authorizing access to aws services.

    As the number of rules per security group is limited to 50,
    we create blocks of 50 rules.

    :param vpc: vpc in which to create the group
    :type vpc: VPC
    :return: a dict of security groups indexed by name
    :rtype: dict(str, SecurityGroup)
    """
    ip_ranges = requests.get(IP_RANGES_URL).json()["prefixes"]

    # Retrieve first the complete list of ipv4 ip ranges for a given region
    amazon_ip_ranges = {
        k["ip_prefix"]
        for k in ip_ranges
        if k["region"] == vpc.region and "ip_prefix" in k and k["service"] == "AMAZON"
    }

    # Sustract the list of ip ranges corresponding to EC2 instances
    ec2_ip_ranges = {
        k["ip_prefix"]
        for k in ip_ranges
        if k["region"] == vpc.region and "ip_prefix" in k and k["service"] == "EC2"
    }
    amazon_ip_ranges -= ec2_ip_ranges

    # Authorize https on the resulting list of ip ranges
    sgs = {}
    i = 0
    limit = 50
    sg_name = name + str(i)
    sg = SecurityGroup(sg_name, vpc, description="Allow acces to amazon services")
    sgs[sg_name] = sg
    for ip_range in amazon_ip_ranges:
        if len(sg.egress + sg.ingress) == limit:
            i += 1
            sg_name = name + str(i)
            sg = SecurityGroup(
                sg_name, vpc, description="Allow acces to amazon services"
            )
            sgs[sg_name] = sg
        sg.add_rule(Ipv4EgressRule("https", ip_range))
    return sgs
