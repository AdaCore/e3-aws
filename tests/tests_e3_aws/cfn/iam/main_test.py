import pytest
from e3.aws.cfn.iam import (
    Allow,
    Deny,
    Group,
    InstanceRole,
    Policy,
    PolicyDocument,
    Principal,
    PrincipalKind,
    User,
)
from e3.aws.cfn.s3 import Bucket


def test_create_statements():
    """Various statement creations."""
    s1 = Deny(
        apply_to=Principal(PrincipalKind.SERVICE, "myservice"),
        to="do_something",
        not_on="resource",
    )
    assert s1.properties

    s2 = Allow(
        apply_to=Principal(PrincipalKind.SERVICE, "myservice"),
        sid="id1",
        to="do_something",
        on="allowed_resource",
    )
    assert s2.properties

    pd1 = PolicyDocument()
    pd2 = PolicyDocument()
    pd1.append(s1)
    pd2.append(s2)
    pd3 = pd1 + pd2
    assert len(pd3.statements) == 2
    pd1 += [s2]
    assert len(pd3.statements) == 2


def test_create_instance_profile():
    """Create a basic instance role that get access to a bucket."""
    s = Bucket("MyBucket")
    policy_document = PolicyDocument()
    policy_document.append(
        Allow().to(["s3:ListBucket", "s3:GetObject", "s3:ListObjects"]).on(s.arn)
    )

    instance_profile = InstanceRole("InstRole")
    instance_profile.add_policy(Policy("Pol", policy_document))
    assert instance_profile.body


def test_principal_star():
    """Create a list of principal with one principal being '*'."""
    pl = [
        Principal(PrincipalKind.SERVICE, "ec2.amazonaws.com"),
        Principal(PrincipalKind.EVERYONE),
    ]
    with pytest.raises(AssertionError):
        Principal.property_list(pl)

    pl = [Principal(PrincipalKind.EVERYONE)]
    assert Principal.property_list(pl)


def test_create_user_and_group():
    """Create a basic group."""
    mygroup = Group("mygroup")
    myuser = User("myuser", groups=[mygroup.name])
    assert myuser.properties["Groups"] == [mygroup.name]
    assert mygroup.properties["GroupName"] == mygroup.name
