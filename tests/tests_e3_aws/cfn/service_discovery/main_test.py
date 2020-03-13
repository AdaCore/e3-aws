from e3.aws.cfn.ec2 import VPC
from e3.aws.cfn.service_discovery import PrivateDnsNamespace


def test_create_privatedns():
    vpc = VPC("myvpc", "10.10.0.0/16")
    p = PrivateDnsNamespace("mypriv", vpc, domain="vpc.", description="Priv Namespace")
    assert p.properties
