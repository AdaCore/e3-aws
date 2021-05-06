from __future__ import annotations
import abc
from enum import Enum
from typing import TYPE_CHECKING

from e3.aws.cfn import AWSType, GetAtt, Resource, Stack

if TYPE_CHECKING:
    from typing import Optional, Any, Iterable


class PrincipalKind(Enum):
    AWS = "AWS"
    FEDERATED = "Federated"
    SERVICE = "Service"
    EVERYONE = "*"


class Principal(object):
    """Represent a principal in an IAM policy."""

    def __init__(self, kind: PrincipalKind, value: Optional[str] = None) -> None:
        """Initialize a Principal.

        :param kind: principal kind
        :param value: string value for the principal. If kind is set
            to EVERYONE value should be None, otherwise value should
            be a string different from '*'
        """
        assert isinstance(kind, PrincipalKind)
        self.kind = kind
        assert (kind == PrincipalKind.EVERYONE and value is None) or (
            value is not None and value != "*"
        )
        self.value = value

    @classmethod
    def property_list(cls, principals):
        """Serialize a list of principal as a simple object.

        :param principals: list of principals
        :type principals: list[Principal]
        :rtype: dict | str
        """
        result = {}
        for principal in principals:

            if principal.kind == PrincipalKind.EVERYONE:
                # If EVERYONE is present then it should be alone because
                # it will mask any other principal.
                assert len(principals) == 1, 'Principal "*" should be used alone'
                result = "*"
                break

            if principal.kind.value not in result:
                result[principal.kind.value] = []
            result[principal.kind.value].append(principal.value)

        return result


class Statement(object, metaclass=abc.ABCMeta):
    """Statement of IAM Policy Document."""

    def __init__(
        self,
        sid: Optional[str] = None,
        to: Optional[list[str] | str] = None,
        on: Optional[list[str] | str] = None,
        not_on: Optional[list[str] | str] = None,
        apply_to: Optional[list[Principal] | Principal] = None,
    ):
        """Initialize a statement.

        :param sid: statement id (optional)
        :param to: one or several action for the statement
        :param on: resource or list of resources on which the statement apply
        :type on: list[str] | str | None
        :param not_on: resource or list of resources on which the statement
            does not apply. Note that not_on and on cannot be both set
        :type not_on: list[str] | str | None
        :param apply_to: list of principals that are targeted by the statement
        :type apply_to: list[Principals] | Principal | None
        """
        self.resources: list[Any] = []
        self.not_resources: list[Any] = []
        self.actions: list[Any] = []
        self.principals: list[Any] = []
        self.sid = sid
        self.condition = None

        if to is not None:
            self.to(to)
        if on is not None:
            self.on(on)
        if not_on is not None:
            self.not_on(not_on)
        if apply_to is not None:
            self.apply_to(apply_to)

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {"Effect": self.EFFECT}
        if self.sid is not None:
            result["Sid"] = self.sid
        if self.resources:
            result["Resource"] = self.resources
        if self.not_resources:
            result["NotResource"] = self.not_resources
        if self.principals:
            result["Principal"] = Principal.property_list(self.principals)
        if self.actions:
            result["Action"] = self.actions
        if self.condition is not None:
            result["Condition"] = self.condition
        return result

    def to(self, actions: Iterable[str] | str | GetAtt) -> Statement:
        """Add action(s) targeted by statement.

        :param actions: one or several action for the statement
        :return: the modified statement
        """
        if isinstance(actions, str) or isinstance(actions, GetAtt):
            self.actions.append(actions)
        else:
            self.actions += actions
        return self

    def on(self, resources: Iterable[str | GetAtt] | str | GetAtt) -> Statement:
        """Add resource(s) on which the statement apply.

        :param resources: resource or list of resources
        :return: the modified statement
        """
        assert not self.not_resources
        if isinstance(resources, str) or isinstance(resources, GetAtt):
            resources = [resources]
        self.resources += resources
        return self

    def not_on(self, resources: Iterable[str | GetAtt] | str | GetAtt) -> Statement:
        """Add resource(s) on which not to apply the statement.

        :param resources: resource or list of resources
        :return: the modified statement
        """
        assert not self.resources
        if isinstance(resources, str) or isinstance(resources, GetAtt):
            resources = [resources]
        self.not_resources += resources
        return self

    def apply_to(self, principals: list[Principal] | Principal) -> Statement:
        """Add principal that can use the statement.

        :param principals: principal list
        :type principals: list[Principal] | Principal
        :return: the modified statement
        :rtype: Statement
        """
        if isinstance(principals, Principal):
            self.principals.append(principals)
        else:
            self.principals += principals
        return self


class Allow(Statement):
    """Allow statement."""

    EFFECT = "Allow"


class Deny(Statement):
    """Deny statement."""

    EFFECT = "Deny"


class PolicyDocument:
    """IAM Policy Document."""

    def __init__(self):
        """Initialize a policy document."""
        self.statements = []

    def append(self, statement):
        """Append a statement.

        :param statement: a IAM Statement
        :type statement: Statement
        :return: the modified policy document
        :rtype: PolicyDocument
        """
        assert isinstance(statement, Statement)
        self.statements.append(statement)
        return self

    def extend(self, statements):
        """Append a list of statements.

        :param statements: IAM Statements
        :type statements: list[Statement]
        :return: the modified policy document
        :rtype: PolicyDocument
        """
        for s in statements:
            assert isinstance(s, Statement)
        self.statements.extend(statements)
        return self

    def __iadd__(self, statements):
        """see extend."""
        return self.extend(statements)

    def __add__(self, other):
        """Add statement(s) or merge two policy documents.

        :param other: statement, list of statements or policy document
        :type other: Statement | list[Statement] | PolicyDocument
        :return: the modified policy document
        :rtype: PolicyDocument
        """
        result = PolicyDocument()
        result.extend(self.statements)
        if isinstance(other, Statement):
            result.append(other)
        elif isinstance(other, PolicyDocument):
            result.extend(other.statements)
        else:
            result.extend(other)
        return result

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        assert self.statements, "A policy should have at least one statement"
        return {
            "Version": "2012-10-17",
            "Statement": [s.properties for s in self.statements],
        }


INSTANCE_ASSUME_ROLE = Allow(
    to="sts:AssumeRole", apply_to=Principal(PrincipalKind.SERVICE, "ec2.amazonaws.com")
)


class Policy(Resource):
    """A CloudFormation Policy resource."""

    def __init__(self, name, policy_document=None, roles=None, groups=None, users=None):
        """Initialize a policy.

        :param name: logical name on the stack
        :type name: str
        :param policy_document: policy document
        :type policy_document: PolicyDocument
        :param roles: list of roles to apply the policy to
        :type roles: list[str] | None
        :param groups: list of groups to apply the policy to
        :type groups: list[str] | None
        :param users: list of users to apply the policy to
        :type users: list[str] | None
        """
        super(Policy, self).__init__(name, kind=AWSType.IAM_POLICY)
        self.roles = roles
        self.groups = groups
        self.users = users
        self.policy_document = policy_document

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {"PolicyName": self.name}
        if self.policy_document is not None:
            result["PolicyDocument"] = self.policy_document.properties

        if self.roles is not None:
            result["Roles"] = self.roles
        if self.groups is not None:
            result["Groups"] = self.groups
        if self.users is not None:
            result["Users"] = self.users
        return result


class InstanceProfile(Resource):
    """IAM Instance profile."""

    def __init__(self, name, role):
        """Initialize an instance profile.

        :param name: logical name in the stack
        :type name: str
        :param role: name of the associated role
        :type role: str
        """
        super(InstanceProfile, self).__init__(name, kind=AWSType.IAM_INSTANCE_PROFILE)
        self.role = role

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        return {"Roles": [self.role], "Path": "/"}


class Role(Resource):
    """IAM Role."""

    def __init__(self, name, assume_role_policy, path="/"):
        """Initialize IAM Role.

        :param name: role name
        :type name: str
        :param assume_role_policy: policy to define who can assume the role
        :type assume_role_policy: PolicyDocument
        :param path: the path associated with this role (default: /)
        :type path: str
        """
        # Note: we don't set RoleName attribute because of limitations during
        # update with cloudform. In that case RoleName is generated directly by
        # Cloud Formation. This is not related to the name of the resource as
        # part of a stack.
        super(Role, self).__init__(name, kind=AWSType.IAM_ROLE)
        self.path = path
        self.policies = []
        self.assume_role_policy = assume_role_policy

    def add(self, policy):
        """Add a policy.

        :param policy: a policy
        :type policy: Policy
        :return: the object itself
        :rtype: Role
        """
        assert isinstance(policy, Policy)
        self.policies.append(policy)
        return self

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        return {
            "AssumeRolePolicyDocument": self.assume_role_policy.properties,
            "Path": self.path,
            "Policies": [p.properties for p in self.policies],
        }


class Group(Resource):
    """IAM Group."""

    ATTRIBUTES = ("Arn",)

    def __init__(self, name, managed_policy_arns=None, path="/"):
        """Initialize IAM Group.

        :param name: group name
        :type name: str
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of
            the IAM managed policies that you want to attach to the user.
        :type managed_policy_arns: list[str] | None
        :param path: the path associated with this role (default: /)
        :type path: str
        """
        super(Group, self).__init__(name, kind=AWSType.IAM_GROUP)
        self.path = path
        self.policies = []
        self.managed_policy_arns = managed_policy_arns or []

    def add(self, policy):
        """Add a policy.

        :param policy: a policy
        :type policy: Policy
        :return: the object itself
        :rtype: Role
        """
        assert isinstance(policy, Policy)
        self.policies.append(policy)
        return self

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        return {
            "ManagedPolicyArns": self.managed_policy_arns,
            "GroupName": self.name,
            "Path": self.path,
            "Policies": [p.properties for p in self.policies],
        }


class User(Resource):
    """IAM User."""

    ATTRIBUTES = ("Arn",)

    def __init__(
        self,
        name,
        groups=None,
        managed_policy_arns=None,
        path="/",
        permissions_boundary=None,
    ):
        """Initialize IAM User.

        :param name: user name
        :type name: str
        :type groups: list[str] | None
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of
            the IAM managed policies that you want to attach to the user.
        :type managed_policy_arns: list[str] | None
        :param path: the path associated with this role (default: /)
        :type path: str
        :param permissions_boundary: The ARN of the policy that is used to set
            the permissions boundary for the user.
        :type permissions_boundary: str | None
        """
        super(User, self).__init__(name, kind=AWSType.IAM_USER)
        self.groups = groups or []
        self.path = path
        self.policies = []
        self.managed_policy_arns = managed_policy_arns or []
        self.permissions_boundary = permissions_boundary

    def add(self, policy):
        """Add a policy.

        :param policy: a policy
        :type policy: Policy
        :return: the object itself
        :rtype: Role
        """
        assert isinstance(policy, Policy)
        self.policies.append(policy)
        return self

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        props = {
            "ManagedPolicyArns": self.managed_policy_arns or [],
            "UserName": self.name,
            "Groups": self.groups,
            "Path": self.path,
            "Policies": [p.properties for p in self.policies],
        }
        if self.permissions_boundary is not None:
            props["PermissionsBoundary"] = self.permissions_boundary
        return props


class InstanceRole(Stack):
    """Instance Role.

    Create both Role and associated profile.
    """

    def __init__(self, name, path="/"):
        """Initialize an instance role.

        :param name: name of the role. The instance profile name will be this
            name + ``InstanceProfile``
        :type name: str
        :param path: path associated with this role
        :type path: str
        """
        super(InstanceRole, self).__init__(name)
        assume_role_policy = PolicyDocument()
        assume_role_policy.append(INSTANCE_ASSUME_ROLE)
        self.add(Role(name, assume_role_policy, path))
        self.add(InstanceProfile(name + "InstanceProfile", self.resources[name].ref))

    def add_policy(self, policy):
        """Add a policy.

        :param policy: a policy
        :type policy: Policy
        :return: the object itself
        :rtype: InstanceRole
        """
        self[self.name].add(policy)
        return self

    @property
    def instance_profile(self):
        """Return the name of the instance profile.

        :return: the name of the instance profile
        :rtype: str
        """
        return self.resources[self.name + "InstanceProfile"]
