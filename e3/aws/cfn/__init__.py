from e3.aws import client
from e3.env import Env
from enum import Enum
import re
import yaml


VALID_STACK_NAME = re.compile('^[a-zA-Z][a-zA-Z0-9-]*$')
VALID_STACK_NAME_MAX_LEN = 128


class AWSType(Enum):
    """Cloud Formation resource types."""

    EC2_EIP = 'AWS::EC2::EIP'
    EC2_INSTANCE = 'AWS::EC2::Instance'
    EC2_INTERNET_GATEWAY = 'AWS::EC2::InternetGateway'
    EC2_NAT_GATEWAY = 'AWS::EC2::NatGateway'
    EC2_NETWORK_INTERFACE = 'AWS::EC2::NetworkInterface'
    EC2_ROUTE = 'AWS::EC2::Route'
    EC2_ROUTE_TABLE = 'AWS::EC2::RouteTable'
    EC2_SECURITY_GROUP = 'AWS::EC2::SecurityGroup'
    EC2_SUBNET = 'AWS::EC2::Subnet'
    EC2_SUBNET_ROUTE_TABLE_ASSOCIATION = \
        'AWS::EC2::SubnetRouteTableAssociation'
    EC2_VOLUME = 'AWS::EC2::Volume'
    EC2_VPC = 'AWS::EC2::VPC'
    EC2_VPC_ENDPOINT = 'AWS::EC2::VPCEndpoint'
    EC2_VPC_GATEWAY_ATTACHMENT = 'AWS::EC2::VPCGatewayAttachment'
    IAM_GROUP = 'AWS::IAM::Group'
    IAM_ROLE = 'AWS::IAM::Role'
    IAM_USER = 'AWS::IAM::User'
    IAM_POLICY = 'AWS::IAM::Policy'
    IAM_INSTANCE_PROFILE = 'AWS::IAM::InstanceProfile'
    ROUTE53_HOSTED_ZONE = 'AWS::Route53::HostedZone'
    ROUTE53_RECORDSET = 'AWS::Route53::RecordSet'
    S3_BUCKET = 'AWS::S3::Bucket'
    S3_BUCKET_POLICY = 'AWS::S3::BucketPolicy'
    SERVICE_DISCOVERY_PRIVATE_DNS_NAMESPACE = \
        'AWS::ServiceDiscovery::PrivateDnsNamespace'
    CODE_COMMIT_REPOSITORY = \
        'AWS::CodeCommit::Repository'


class GetAtt(object):
    """Intrinsic function Fn::Getatt."""

    def __init__(self, name, attribute):
        """Initialize a Getatt instance.

        :param name: resource name
        :type name: str
        :param attribute: attribute name
        :type attribute: str
        """
        self.name = name
        self.attribute = attribute


class Ref(object):
    """Intrinsic function Fn::Ref."""

    def __init__(self, name):
        """Initialize a reference.

        :param name: resource name
        :type name: str
        """
        self.name = name


class Base64(object):
    """Intrinsic function Fn::Base64."""

    def __init__(self, content):
        """Initialize a base64 content.

        :param content: content to be encoded into base64
        :type content: str
        """
        self.content = content


class Join(object):
    """Intrinsic function Fn::Join."""

    def __init__(self, content, delimiter=""):
        """Initialize a Join object.

        :param content: a list
        :type content: list
        :param delimiter: a join delimiter
        :type delimiter: str
        """
        self.content = content
        self.delimiter = delimiter


# Declare Yaml representer for intrinsic functions

def getatt_representer(dumper, data):
    return dumper.represent_scalar(
        '!GetAtt', '%s.%s' % (data.name, data.attribute))


def ref_representer(dumper, data):
    return dumper.represent_scalar('!Ref', data.name)


def base64_representer(dumper, data):
    return dumper.represent_dict({"Fn::Base64": data.content})


def join_representer(dumper, data):
    return dumper.represent_sequence('!Join', [data.delimiter, data.content])


class CFNYamlDumper(yaml.Dumper):
    def __init__(self, *args, **kwargs):
        """Yaml dumper for cloud formation templates.

        See yaml.Dumper documentation.
        """
        super(CFNYamlDumper, self).__init__(*args, **kwargs)

        self.add_representer(GetAtt, getatt_representer)
        self.add_representer(Ref, ref_representer)
        self.add_representer(Base64, base64_representer)
        self.add_representer(Join, join_representer)

    def ignore_aliases(self, data):
        """Ignore aliases."""
        return True


class Resource(object):
    """A CloudFormation resource."""

    # List of valid attribute names
    ATTRIBUTES = ()

    def __init__(self, name, kind):
        """Initialize a resource.

        :param name: name of the resource (alphanumeric)
        :type name: str
        :param kind: resource kind
        :type kind: e3.aws.cfn.types.AWSType
        """
        assert isinstance(kind, AWSType), \
            'resource kind should be an AWSType: found %s' % kind
        assert name.isalnum(), \
            'resource name should be alphanumeric: found %s' % name
        self.name = name
        self.kind = kind
        self.depends = None

        # Track region in which the resource is created
        e = Env()
        if hasattr(e, 'aws_env'):
            self.region = Env().aws_env.default_region
        else:
            self.region = 'invalid-region'
        self.metadata = {}

    def getatt(self, name):
        """Return an attribute reference.

        :param name: attribute name. should one of the valid attribute
            declared in ATTRIBUTES class variable
        :type name: str
        :return: a getatt object
        :rtype: e3.aws.cfn.types.GetAtt

        """
        assert name in self.ATTRIBUTES, 'invalid attribute %s' % name
        return GetAtt(self.name, name)

    @property
    def ref(self):
        """Return a reference to the current resource.

        :return: a reference
        :rtype: e3.aws.cfn.types.Ref
        """
        return Ref(self.name)

    @property
    def properties(self):
        """Return the resource properties dict.

        :return: the resources Properties key value for the current resource.
        :rtype: dict
        """
        return {}

    def export(self):
        """Export resource as a template fragment.

        :return: the dict representing the resources. The resulting dict can
            be serialized using Yaml to get a valid CloudFormation template
            fragment
        :rtype: dict
        """
        result = {'Type': self.kind.value,
                  'Properties': self.properties}
        if self.depends is not None:
            result['DependsOn'] = self.depends
        if self.metadata:
            result['Metadata'] = self.metadata
        return result


class Stack(object):
    """A CloudFormation stack."""

    def __init__(self, name, description=None):
        """Initialize a stack.

        :param name: stack name
        :type name: str
        :param description: a description of the stack
        :type description: str | None
        """
        assert re.match(VALID_STACK_NAME, name) and \
            len(name) <= VALID_STACK_NAME_MAX_LEN, \
            'invalid stack name: %s' % name
        self.resources = {}
        self.name = name
        self.description = description

    def add(self, element):
        """Add a resource or merge a stack.

        :param element: if a resource add the resource to the stack. If a stack
            merge its resources into the current stack.
        :type element: Stack | Resources
        :return: the current stack
        :rtype: Stack
        """
        assert isinstance(element, Resource) or isinstance(element, Stack), \
            "a resource or a stack is expected. got %s" % element
        assert element.name not in self.resources, \
            'resource already exist: %s' % element.name
        self.resources[element.name] = element
        return self

    def __iadd__(self, element):
        """Add a resource or merge a stack.

        :param element: if a resource add the resource to the stack. If a stack
            merge its resources into the current stack.
        :type element: Stack | Resources
        :return: the current stack
        :rtype: Stack
        """
        return self.add(element)

    def __getitem__(self, key):
        if key not in self.resources:
            raise KeyError
        return self.resources[key]

    def __contains__(self, key):
        return key in self.resources

    def export(self):
        """Export stack as dict.

        :return: a dict that can be serialized as YAML to produce a template
        :rtype: dict
        """
        resources = {}
        for resource in self.resources.values():
            if isinstance(resource, Resource):
                assert resource.name not in resources
                resources[resource.name] = resource.export()
            else:
                # resource is a stack
                stack_resources = resource.export()['Resources']
                for k, v in stack_resources.items():
                    assert k not in resources
                    resources[k] = v

        result = {
            'AWSTemplateFormatVersion': '2010-09-09',
            'Resources': resources}
        if self.description is not None:
            result['Description'] = self.description
        return result

    @property
    def body(self):
        """Export stack as a CloudFormation template.

        :return: a valid CloudFormation template
        :rtype: str
        """
        return yaml.dump(self.export(), Dumper=CFNYamlDumper)

    @client('cloudformation')
    def describe(self, client):
        """Describe a stack.

        :return: the stack metadata
        :rtype: dict
        """
        aws_result = client.describe_stacks(
            StackName=self.name)['Stacks'][0]
        return aws_result

    @client('cloudformation')
    def create(self, client, url=None):
        """Create a stack.

        :param client: a botocore client
        :type client: botocore.client.Client. This parameter is handled by the
            decorator
        param url: url of the template body in S3. When not None this suppose
            the user has uploaded the template body on S3 first at the given
            url. Use S3 to refer to the template body rather than using inline
            version allows to use template of size up to 500Ko instead of
            50Ko.
        :type url: str | None
        """
        if url is None:
            return client.create_stack(
                StackName=self.name,
                TemplateBody=self.body,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'])
        else:
            return client.create_stack(
                StackName=self.name,
                TemplateURL=url,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'])

    def exists(self):
        """Check if a given stack exists.

        :return: True if it does, False otherwise
        """
        try:
            self.state()
            return True
        except Exception:
            return False

    @client('cloudformation')
    def state(self, client):
        """Return state of the stack on AWS."""
        return client.describe_stacks(StackName=self.name)

    @client('cloudformation')
    def validate(self, client, url=None):
        """Validate a template.

        :param client: a botocore client
        :type client: botocore.client.Client. This parameter is handled by the
            decorator
        param url: url of the template body in S3. When not None this suppose
            the user has uploaded the template body on S3 first at the given
            url. Use S3 to refer to the template body rather than using inline
            version allows to use template of size up to 500Ko instead of
            50Ko.
        :type url: str | None
        """
        if url is None:
            return client.validate_template(TemplateBody=self.body)
        else:
            return client.validate_template(TemplateURL=url)

    @client('cloudformation')
    def create_change_set(self, name, client, url=None):
        """Create a change set.

        This creates a difference between the state of the stack on AWS servers
        and the current one generated with e3-aws.

        :param client: a botocore client. This parameter is handled by the
            decorator
        :type client: botocore.client.Client
        :param name: name of the changeset
        :type name: str
        :param url: url of the template body in S3. When not None this suppose
            the user has uploaded the template body on S3 first at the given
            url. Use S3 to refer to the template body rather than using inline
            version allows to use template of size up to 500Ko instead of
            50Ko.
        :type url: str | None
        """
        if url is None:
            return client.create_change_set(
                ChangeSetName=name,
                StackName=self.name,
                TemplateBody=self.body,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'])
        else:
            return client.create_change_set(
                ChangeSetName=name,
                StackName=self.name,
                TemplateURL=url,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'])

    @client('cloudformation')
    def describe_change_set(self, name, client):
        """Describe a change set.

        Retrieve status of a given changeset

        :param client: a botocore client
        :type client: botocore.client.Client
        :param name: name of the changeset
        :type name: str
        """
        return client.describe_change_set(ChangeSetName=name,
                                          StackName=self.name)

    @client('cloudformation')
    def delete_change_set(self, name, client):
        """Delete a change set.

        :param client: a botocore client
        :type client: botocore.client.Client
        :param name: name of the changeset
        :type name: str
        """
        return client.delete_change_set(ChangeSetName=name,
                                        StackName=self.name)

    @client('cloudformation')
    def delete(self, client):
        """Delete a stack.

        Delete a stack. Note that operation is aynchron

        :param client: a botocore client
        :type client: botocore.client.Client
        """
        return client.delete_stack(StackName=self.name)

    @client('cloudformation')
    def cost(self, client):
        """Compute cost of the stack (estimation).

        :param client: a botocore client
        :type client: botocore.client.BaseClient
        """
        return client.estimate_template_cost(TemplateBody=self.body)

    @client('cloudformation')
    def execute_change_set(self, client, changeset_name, wait=False):
        """Execute a changeset.

        :param client: a botocore client
        :type client: botocore.client.BaseClient
        :param changeset_name: name of the changeset to apply
        :type changeset_name: str
        :param wait: whether to wait for the completion of the command
        :type wait: bool
        """
        client.execute_change_set(
            ChangeSetName=changeset_name,
            StackName=self.name)

        if wait:
            waiter = client.get_waiter('stack_update_complete')
            print('... waiting for stack update')
            waiter.wait(StackName=self.name)
            print('done')

    @client('cloudformation')
    def resource_status(self, client, in_progress_only=True):
        """Return status of each resources of the stack.

        The state of the stack taken is the one pushed on AWS (after a call
        to create for example).

        :param client: a botocore client
        :type client: botocore.client.BaseClient
        :param in_progress_only: if True return only resources that are in
            one of the "PROGRESS" state (deletion, creation, ...)
        :type in_progress_only: bool
        :return: a dict associating a resource logical name to a status name
        :rtype: dict
        """
        aws_result = client.describe_stack_resources(StackName=self.name)
        assert 'StackResources' in aws_result
        result = {}
        for res in aws_result['StackResources']:
            if 'PROGRESS' in res['ResourceStatus'] or not in_progress_only:
                result[res['LogicalResourceId']] = res['ResourceStatus']
        return result

    @client('cloudformation')
    def enable_termination_protection(self, client):
        """Enable termination protection for a stack."""
        aws_result = self.describe()
        if aws_result['EnableTerminationProtection']:
            print("Stack termination protection is already enabled")
            return

        aws_result = client.update_termination_protection(
            EnableTerminationProtection=True,
            StackName=self.name)
        assert 'StackId' in aws_result
        print("Stack termination protection enabled")

    @client('cloudformation')
    def set_stack_policy(self, stack_policy_body, client):
        """Set a stack policy.

        :param stack_policy_body: stack policy body to apply
        :type stack_policy_body: str
        """
        aws_result = client.get_stack_policy(
            StackName=self.name)

        if stack_policy_body != aws_result['StackPolicyBody']:
            print("Stack policy has been modified")

            client.set_stack_policy(
                StackName=self.name,
                StackPolicyBody=stack_policy_body)
        else:
            print("Stack policy already up-to-date")
