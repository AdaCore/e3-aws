import abc

from e3.aws.cfn import AWSType, GetAtt, Resource, Stack


class Statement(object, metaclass=abc.ABCMeta):
    """Statement of IAM Policy Document."""

    def __init__(self,
                 sid=None,
                 to=None,
                 on=None,
                 not_on=None,
                 service=None):
        """Initialize a statement.

        :param sid: statement id (optional)
        :type sid: str
        :param to: one or several action for the statement
        :type to: list[str] | str | None
        :param on: resource or list of resources on which the statement apply
        :type on: list[str] | str | None
        :param not_on: resource or list of resources on which the statement
            does not apply. Note that not_on and on cannot be both set
        :type not_on: list[str] | str | None
        :param services: service of list of services that can use that
            statement
        :type services: list[str] | str | None
        """
        self.resources = []
        self.not_resources = []
        self.actions = []
        self.principals = {}
        self.sid = sid

        if to is not None:
            self.to(to)
        if on is not None:
            self.on(on)
        if not_on is not None:
            self.not_on(not_on)
        if service is not None:
            self.service(service)

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        result = {'Effect': self.EFFECT}
        if self.sid is not None:
            result['Sid'] = self.sid
        if self.resources:
            result['Resource'] = self.resources
        if self.not_resources:
            result['NotResource'] = self.not_resources
        if self.principals:
            result['Principal'] = self.principals
        if self.actions:
            result['Action'] = self.actions
        return result

    def to(self, actions):
        """Add action(s) targeted by statement.

        :param actions: one or several action for the statement
        :type actions: collections.Iterable[str] | str | GetAtt
        :return: the modified statement
        :rtype: Statement
        """
        if isinstance(actions, str) or isinstance(actions, GetAtt):
            self.actions.append(actions)
        else:
            self.actions += actions
        return self

    def on(self, resources):
        """Add resource(s) on which the statement apply.

        :param resources: resource or list of resources
        :type resources: list[str] | str | GetAtt
        :return: the modified statement
        :rtype: Statement
        """
        assert not self.not_resources
        if isinstance(resources, str) or isinstance(resources, GetAtt):
            resources = [resources]
        self.resources += resources
        return self

    def not_on(self, resources):
        """Add resource(s) on which not to apply the statement.

        :param resources: resource or list of resources
        :type resources: list[str] | str | GetAtt
        :return: the modified statement
        :rtype: Statement
        """
        assert not self.resources
        if isinstance(resources, str) or isinstance(resources, GetAtt):
            resources = [resources]
        self.not_resources += resources
        return self

    def for_service(self, services):
        """Add service that can use the statement.

        :param services: service of list of services
        :type services: list[str] | str | GetAtt
        :return: the modified statement
        :rtype: Statement
        """
        if isinstance(services, str) or isinstance(services, GetAtt):
            services = [services]
        if 'Service' not in self.principals:
            self.principals['Service'] = []
        self.principals['Service'] += services
        return self

    # Declare an alias
    service = for_service


class Allow(Statement):
    """Allow statement."""

    EFFECT = 'Allow'


class Deny(Statement):
    """Deny statement."""

    EFFECT = 'Deny'


class PolicyDocument(object):
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
        assert self.statements, 'A policy should have at least one statement'
        return {'Version': '2012-10-17',
                'Statement': [s.properties for s in self.statements]}


INSTANCE_ASSUME_ROLE = Allow().to(
    'sts:AssumeRole').for_service('ec2.amazonaws.com')


class Policy(Resource):
    """A CloudFormation Policy resource."""

    def __init__(self,
                 name,
                 policy_document=None,
                 roles=None,
                 groups=None,
                 users=None):
        """Initialize a policy.

        :param name: logical name on the stack
        :type name: str
        :param policy_document: policy document
        :type policy_document: PolicyDocument
        :param roles: list of roles to apply the policy to
        :type roles: list[str] | None
        :param groups: list of groupss to apply the policy to
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
        result = {'PolicyName': self.name}
        if self.policy_document is not None:
            result['PolicyDocument'] = self.policy_document.properties

        if self.roles is not None:
            result['Roles'] = self.roles
        if self.groups is not None:
            result['Groups'] = self.groups
        if self.users is not None:
            result['Users'] = self.users
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
        super(InstanceProfile, self).__init__(
            name,
            kind=AWSType.IAM_INSTANCE_PROFILE)
        self.role = role

    @property
    def properties(self):
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.

        :rtype: dict
        """
        return {'Roles': [self.role],
                'Path': '/'}


class Role(Resource):
    """IAM Role."""

    def __init__(self, name, assume_role_policy, path='/'):
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
        return {'AssumeRolePolicyDocument': self.assume_role_policy.properties,
                'Path': self.path,
                'Policies': [p.properties for p in self.policies]}


class InstanceRole(Stack):
    """Instance Role.

    Create both Role and associated profile.
    """

    def __init__(self, name, path='/'):
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
        self.add(InstanceProfile(name + 'InstanceProfile',
                                 self.resources[name].ref))

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
        return self.resources[self.name + 'InstanceProfile']
