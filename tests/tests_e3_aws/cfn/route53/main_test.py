from e3.aws.cfn.ec2 import VPC
from e3.aws.cfn.route53 import HostedZone, RecordSet


def test_create_recordset():
    """RecordSet test."""
    r = RecordSet(
        "myrecordset",
        hosted_zone="example.com.",
        dns_name="myserver.example.com",
        dns_type="A",
        ttl=60,
        resource_records=["1.1.1.1"],
    )
    assert r.properties


def test_create_hosted_zone():
    """Hosted Zone test."""
    public_hz = HostedZone("myhostedzone", "example.com.")
    assert public_hz.properties

    vpc = VPC("myvpc", "192.168.0.0/16")
    private_hz = HostedZone("privhostedzone", "local.com.", vpcs=[vpc])
    assert private_hz.properties
