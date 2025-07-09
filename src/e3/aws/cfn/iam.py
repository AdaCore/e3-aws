from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING

from e3.aws.cfn import AWSType, GetAtt, Join, Resource, Stack

if TYPE_CHECKING:
    from typing import Any, Iterable, Self

    from e3.aws.cfn import Ref


class PrincipalKind(Enum):
    AWS = "AWS"
    FEDERATED = "Federated"
    SERVICE = "Service"
    EVERYONE = "*"


class Principal(object):
    """Represent a principal in an IAM policy."""

    def __init__(self, kind: PrincipalKind, value: str | None = None) -> None:
        """Initialize a Principal.

        :param kind: principal kind
        :param value: string value for the principal. If kind is set
            to EVERYONE value should be None, otherwise value should
            be a string different from '*'
        """
        self.kind = kind
        assert (kind == PrincipalKind.EVERYONE and value is None) or (
            value is not None and value != "*"
        )
        self.value = value

    @classmethod
    def property_list(cls, principals: list[Principal]) -> dict[str, list[str]] | str:
        """Serialize a list of principal as a simple object.

        :param principals: list of principals
        """
        result: dict[str, list[str]] = {}
        for principal in principals:
            if principal.kind == PrincipalKind.EVERYONE:
                # If EVERYONE is present then it should be alone because
                # it will mask any other principal.
                assert len(principals) == 1, 'Principal "*" should be used alone'
                return "*"

            if principal.kind.value not in result:
                result[principal.kind.value] = []
            assert principal.value is not None
            result[principal.kind.value].append(principal.value)

        return result


class Statement(object):
    """Statement of IAM Policy Document."""

    EFFECT: str = ""

    def __init__(
        self,
        sid: str | None = None,
        to: list[str] | str | None = None,
        on: list[str | Join] | str | None = None,
        not_on: list[str] | str | None = None,
        apply_to: list[Principal] | Principal | None = None,
    ) -> None:
        """Initialize a statement.

        :param sid: statement id (optional)
        :param to: one or several action for the statement
        :param on: resource or list of resources on which the statement apply
        :param not_on: resource or list of resources on which the statement
            does not apply. Note that not_on and on cannot be both set
        :param apply_to: list of principals that are targeted by the statement
        """
        self.resources: list[Any] = []
        self.not_resources: list[Any] = []
        self.actions: list[Any] = []
        self.principals: list[Any] = []
        self.sid = sid
        self.condition: Any | None = None

        if to is not None:
            self.to(to)
        if on is not None:
            self.on(on)
        if not_on is not None:
            self.not_on(not_on)
        if apply_to is not None:
            self.apply_to(apply_to)

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {"Effect": self.EFFECT}
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

    def on(
        self, resources: Iterable[str | GetAtt | Join] | str | GetAtt | Join
    ) -> Statement:
        """Add resource(s) on which the statement apply.

        :param resources: resource or list of resources
        :return: the modified statement
        """
        assert not self.not_resources
        if isinstance(resources, (str, GetAtt, Join)):
            resources = [resources]
        self.resources += resources
        return self

    def not_on(
        self, resources: Iterable[str | GetAtt | Join] | str | GetAtt | Join
    ) -> Statement:
        """Add resource(s) on which not to apply the statement.

        :param resources: resource or list of resources
        :return: the modified statement
        """
        assert not self.resources
        if isinstance(resources, (str, GetAtt, Join)):
            resources = [resources]
        self.not_resources += resources
        return self

    def apply_to(self, principals: list[Principal] | Principal) -> Statement:
        """Add principal that can use the statement.

        :param principals: principal list
        :return: the modified statement
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

    def __init__(self) -> None:
        """Initialize a policy document."""
        self.statements: list[Statement] = []

    def append(self, statement: Statement) -> PolicyDocument:
        """Append a statement.

        :param statement: a IAM Statement
        :return: the modified policy document
        """
        self.statements.append(statement)
        return self

    def extend(self, statements: list[Statement]) -> PolicyDocument:
        """Append a list of statements.

        :param statements: IAM Statements
        :return: the modified policy document
        """
        self.statements.extend(statements)
        return self

    def __iadd__(self, statements: list[Statement]) -> PolicyDocument:  # type: ignore[misc]
        """see extend."""
        return self.extend(statements)

    def __add__(
        self, other: Statement | list[Statement] | PolicyDocument
    ) -> PolicyDocument:
        """Add statement(s) or merge two policy documents.

        :param other: statement, list of statements or policy document
        :return: the modified policy document
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
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
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

    def __init__(
        self,
        name: str,
        policy_document: PolicyDocument | None = None,
        roles: list[str] | None = None,
        groups: list[str] | None = None,
        users: list[str] | None = None,
    ) -> None:
        """Initialize a policy.

        :param name: logical name on the stack
        :param policy_document: policy document
        :param roles: list of roles to apply the policy to
        :param groups: list of groups to apply the policy to
        :param users: list of users to apply the policy to
        """
        super(Policy, self).__init__(name, kind=AWSType.IAM_POLICY)
        self.roles = roles
        self.groups = groups
        self.users = users
        self.policy_document = policy_document

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        result: dict[str, Any] = {"PolicyName": self.name}
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

    def __init__(self, name: str, role: str | Ref) -> None:
        """Initialize an instance profile.

        :param name: logical name in the stack
        :param role: name of the associated role
        """
        super(InstanceProfile, self).__init__(name, kind=AWSType.IAM_INSTANCE_PROFILE)
        self.role = role

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        return {"Roles": [self.role], "Path": "/"}


class Role(Resource):
    """IAM Role."""

    def __init__(
        self, name: str, assume_role_policy: PolicyDocument, path: str = "/"
    ) -> None:
        """Initialize IAM Role.

        :param name: role name
        :param assume_role_policy: policy to define who can assume the role
        :param path: the path associated with this role (default: /)
        """
        # Note: we don't set RoleName attribute because of limitations during
        # update with cloudform. In that case RoleName is generated directly by
        # Cloud Formation. This is not related to the name of the resource as
        # part of a stack.
        super(Role, self).__init__(name, kind=AWSType.IAM_ROLE)
        self.path = path
        self.policies: list[Policy] = []
        self.assume_role_policy = assume_role_policy

    def add(self, policy: Policy) -> Role:
        """Add a policy.

        :param policy: a policy
        :return: the object itself
        """
        self.policies.append(policy)
        return self

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        return {
            "AssumeRolePolicyDocument": self.assume_role_policy.properties,
            "Path": self.path,
            "Policies": [p.properties for p in self.policies],
        }


class Group(Resource):
    """IAM Group."""

    ATTRIBUTES = ("Arn",)

    def __init__(
        self, name: str, managed_policy_arns: list[str] | None = None, path: str = "/"
    ) -> None:
        """Initialize IAM Group.

        :param name: group name
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of
            the IAM managed policies that you want to attach to the user.
        :param path: the path associated with this role (default: /)
        """
        super(Group, self).__init__(name, kind=AWSType.IAM_GROUP)
        self.path = path
        self.policies: list[Policy] = []
        self.managed_policy_arns = managed_policy_arns or []

    def add(self, policy: Policy) -> Group:
        """Add a policy.

        :param policy: a policy
        :return: the object itself
        """
        self.policies.append(policy)
        return self

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
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
        name: str,
        groups: list[str] | None = None,
        managed_policy_arns: list[str] | None = None,
        path: str = "/",
        permissions_boundary: str | None = None,
    ) -> None:
        """Initialize IAM User.

        :param name: user name
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of
            the IAM managed policies that you want to attach to the user.
        :param path: the path associated with this role (default: /)
        :param permissions_boundary: The ARN of the policy that is used to set
            the permissions boundary for the user.
        """
        super(User, self).__init__(name, kind=AWSType.IAM_USER)
        self.groups = groups or []
        self.path = path
        self.policies: list[Policy] = []
        self.managed_policy_arns = managed_policy_arns or []
        self.permissions_boundary = permissions_boundary

    def add(self, policy: Policy) -> Self:
        """Add a policy.

        :param policy: a policy
        :return: the object itself
        """
        self.policies.append(policy)
        return self

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
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

    def __init__(self, name: str, path: str = "/") -> None:
        """Initialize an instance role.

        :param name: name of the role. The instance profile name will be this
            name + ``InstanceProfile``
        :param path: path associated with this role
        """
        super(InstanceRole, self).__init__(name)
        assume_role_policy = PolicyDocument()
        assume_role_policy.append(INSTANCE_ASSUME_ROLE)
        role = Role(name, assume_role_policy, path)
        self.add(role)
        self.add(InstanceProfile(name + "InstanceProfile", role.ref))

    def add_policy(self, policy: Policy) -> InstanceRole:
        """Add a policy.

        :param policy: a policy
        :return: the object itself
        """
        resource = self[self.name]
        assert isinstance(resource, Role)
        resource.add(policy)
        return self

    @property
    def instance_profile(self) -> InstanceProfile:
        """Return the name of the instance profile.

        :return: the name of the instance profile
        """
        resource = self.resources[self.name + "InstanceProfile"]
        assert isinstance(resource, InstanceProfile)
        return resource
