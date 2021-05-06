from __future__ import annotations
from e3.env import Env
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
import re
import time
import uuid
import yaml
import logging

if TYPE_CHECKING:
    import botocore.client
    from typing import Iterator, Optional, Iterable, Callable, Any

VALID_STACK_NAME = re.compile("^[a-zA-Z][a-zA-Z0-9-]*$")
VALID_STACK_NAME_MAX_LEN = 128


def client(name: str) -> Callable:
    """Decorate a function to handle automatically AWS client retrieval.

    The function in input should take a mandatory argument called client.
    The function seen by the user will have an optional argument region
    to select the region in which the client is created.

    :param name: client name
    :type name: str
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            aws_env = Env().aws_env
            if "region" in kwargs:
                region = kwargs["region"]
                del kwargs["region"]
            else:
                region = aws_env.default_region
            client = aws_env.client(name, region=region)
            return func(*args, client=client, **kwargs)

        return wrapper

    return decorator


class AWSType(Enum):
    """Cloud Formation resource types."""

    EC2_EIP = "AWS::EC2::EIP"
    EC2_INSTANCE = "AWS::EC2::Instance"
    EC2_INTERNET_GATEWAY = "AWS::EC2::InternetGateway"
    EC2_LAUNCH_TEMPLATE = "AWS::EC2::LaunchTemplate"
    EC2_NAT_GATEWAY = "AWS::EC2::NatGateway"
    EC2_NETWORK_INTERFACE = "AWS::EC2::NetworkInterface"
    EC2_ROUTE = "AWS::EC2::Route"
    EC2_ROUTE_TABLE = "AWS::EC2::RouteTable"
    EC2_SECURITY_GROUP = "AWS::EC2::SecurityGroup"
    EC2_SUBNET = "AWS::EC2::Subnet"
    EC2_SUBNET_ROUTE_TABLE_ASSOCIATION = "AWS::EC2::SubnetRouteTableAssociation"
    EC2_VOLUME = "AWS::EC2::Volume"
    EC2_VPC = "AWS::EC2::VPC"
    EC2_VPC_ENDPOINT = "AWS::EC2::VPCEndpoint"
    EC2_VPC_GATEWAY_ATTACHMENT = "AWS::EC2::VPCGatewayAttachment"
    IAM_GROUP = "AWS::IAM::Group"
    IAM_ROLE = "AWS::IAM::Role"
    IAM_USER = "AWS::IAM::User"
    IAM_POLICY = "AWS::IAM::Policy"
    IAM_INSTANCE_PROFILE = "AWS::IAM::InstanceProfile"
    ROUTE53_HOSTED_ZONE = "AWS::Route53::HostedZone"
    ROUTE53_RECORDSET = "AWS::Route53::RecordSet"
    S3_BUCKET = "AWS::S3::Bucket"
    S3_BUCKET_POLICY = "AWS::S3::BucketPolicy"
    SERVICE_DISCOVERY_PRIVATE_DNS_NAMESPACE = (
        "AWS::ServiceDiscovery::PrivateDnsNamespace"
    )
    CODE_COMMIT_REPOSITORY = "AWS::CodeCommit::Repository"


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


class Sub(object):
    """Intrinsic function Fn::Sub."""

    def __init__(self, content, variables=None):
        """Initialize a Sub object.

        :param content: a string
        :type content: str
        :param variables: a dict asssociating a key to a value
        :type variables: dict(str, str)
        """
        self.content = content
        if variables:
            self.variables = dict(variables)
        else:
            self.variables = None


# Declare Yaml representer for intrinsic functions


def getatt_representer(dumper, data):
    return dumper.represent_scalar("!GetAtt", "%s.%s" % (data.name, data.attribute))


def ref_representer(dumper, data):
    return dumper.represent_scalar("!Ref", data.name)


def base64_representer(dumper, data):
    return dumper.represent_dict({"Fn::Base64": data.content})


def sub_representer(dumper, data):
    if data.variables:
        return dumper.represent_sequence("!Sub", [data.content, data.variables])
    else:
        return dumper.represent_scalar("!Sub", data.content)


def join_representer(dumper, data):
    return dumper.represent_sequence("!Join", [data.delimiter, data.content])


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
        self.add_representer(Sub, sub_representer)

    def ignore_aliases(self, data):
        """Ignore aliases."""
        return True


class Resource:
    """A CloudFormation resource."""

    # List of valid attribute names
    ATTRIBUTES: Iterable[str] = ()

    def __init__(self, name: str, kind: AWSType):
        """Initialize a resource.

        :param name: name of the resource (alphanumeric)
        :param kind: resource kind
        """
        assert isinstance(kind, AWSType), (
            "resource kind should be an AWSType: found %s" % kind
        )
        assert name.isalnum(), "resource name should be alphanumeric: found %s" % name
        self.name = name
        self.kind = kind
        self.depends = None

        # Track region in which the resource is created
        e = Env()
        if hasattr(e, "aws_env"):
            self.region = Env().aws_env.default_region
        else:
            self.region = "invalid-region"
        self.metadata: dict = {}

    def getatt(self, name):
        """Return an attribute reference.

        :param name: attribute name. should one of the valid attribute
            declared in ATTRIBUTES class variable
        :type name: str
        :return: a getatt object
        :rtype: e3.aws.cfn.types.GetAtt

        """
        assert name in self.ATTRIBUTES, "invalid attribute %s" % name
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

    def export(self) -> dict:
        """Export resource as a template fragment.

        :return: the dict representing the resources. The resulting dict can
            be serialized using Yaml to get a valid CloudFormation template
            fragment
        """
        result = {"Type": self.kind.value, "Properties": self.properties}
        if self.depends is not None:
            result["DependsOn"] = self.depends  # type: ignore
        if self.metadata:
            result["Metadata"] = self.metadata
        return result

    def create_data_dir(self, root_dir: str) -> None:
        """Put data in root_dir before export to S3 bucket referenced by the stack.

        :param root_dir: local directory in which data should be stored. Data will
            be then uploaded to an S3 bucket accessible from the template.
        """
        pass


class StackEventOperation(Enum):
    """Operations associated with stack events."""

    create = "CREATE"
    delete = "DELETE"
    update = "UPDATE"
    update_rollback = "UPDATE_ROLLBACK"
    import_resource = "IMPORT"
    import_rollback = "IMPORT_ROLLBACK"
    rollback = "ROLLBACK"

    def __str__(self) -> str:
        return {
            "CREATE": "creation",
            "DELETE": "deletion",
            "UPDATE": "update",
            "IMPORT": "import",
            "IMPORT_ROLLBACK": "import rollback",
            "UPDATE_ROLLBACK": "update rollback",
            "ROLLBACK": "rollback",
        }[self.value]


class StackEventState(Enum):
    """Operation states associated with stack events."""

    in_progress = "IN_PROGRESS"
    failed = "FAILED"
    complete = "COMPLETE"
    skipped = "SKIPPED"

    def __str__(self) -> str:
        return {
            "IN_PROGRESS": "started",
            "FAILED": "failed",
            "COMPLETE": "completed",
            "SKIPPED": "skipped",
        }[self.value]


class StackEventStatus:
    """Stack event status.

    This represents the combination of an operation and its current state

    :ivar operation: the operation name
    :ivar state: the operation state
    """

    def __init__(self, operation: StackEventOperation, state: StackEventState) -> None:
        """Initialize a stack event status.

        :param operation: an operation
        :param state: an operation state
        """
        self.operation = operation
        self.state = state

    @classmethod
    def from_str(cls, event_status_str: str) -> StackEventStatus:
        """Create a StackEventStatus based on string returned by AWS CFN.

        :param event_status_str: a string representing the status
        :return: a StackEventStatus
        """
        match = re.match(
            r"(CREATE|DELETE|UPDATE|IMPORT|IMPORT_ROLLBACK|UPDATE_ROLLBACK|ROLLBACK)_"
            r"(IN_PROGRESS|FAILED|COMPLETE|SKIPPED)",
            event_status_str,
        )
        assert match is not None, f"invalid event status {event_status_str}"
        return cls(
            operation=StackEventOperation(match.group(1)),
            state=StackEventState(match.group(2)),
        )

    def __str__(self) -> str:
        return f"{self.operation} {self.state}"


class StackEvent:
    """A stack event (see describe_stack_events API)."""

    def __init__(
        self,
        stack_id: str,
        event_id: str,
        stack_name: str,
        logical_resource_id: str,
        physical_resource_id: str,
        resource_type: str,
        timestamp: datetime,
        resource_status: StackEventStatus,
        client_token: Optional[str] = None,
        resource_status_reason: str = "",
        resource_properties: str = "",
    ) -> None:
        """Create a stack event."""
        self.stack_id = stack_id
        self.event_id = event_id
        self.stack_name = stack_name
        self.logical_resource_id = logical_resource_id
        self.physical_resource_id = physical_resource_id
        self.resource_type = resource_type
        self.timestamp = timestamp
        self.resource_status = resource_status
        self.client_token = client_token
        self.resource_status_reason = resource_status_reason
        self.resource_properties = resource_properties

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StackEvent:
        """Create a stack event from a dict as returned by AWS API."""
        return cls(
            stack_id=data["StackId"],
            event_id=data["EventId"],
            stack_name=data["StackName"],
            logical_resource_id=data["LogicalResourceId"],
            physical_resource_id=data["PhysicalResourceId"],
            resource_type=data["ResourceType"],
            timestamp=data["Timestamp"],
            resource_status=StackEventStatus.from_str(data["ResourceStatus"]),
            client_token=data.get("ClientRequestToken", None),
            resource_status_reason=data.get("ResourceStatusReason", ""),
            resource_properties=data.get("ResourceProperties", ""),
        )

    def __str__(self) -> str:
        return (
            f"{self.logical_resource_id:<32}: {self.resource_type:<32}: "
            + f"{str(self.resource_status):<16} ({self.resource_status_reason})"
        )


class Stack(object):
    """A CloudFormation stack."""

    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        cfn_role_arn: Optional[str] = None,
        s3_bucket: Optional[str] = None,
        s3_key: Optional[str] = None,
    ):
        """Initialize a stack.

        :param name: stack name
        :param description: a description of the stack
        :param cfn_role_arn: Arn of the role to be assumed by cloudformation. If
            None then use user role. In the future role_arn should be mandatory in
            order to avoid giving users too much rights.
        :param s3_bucket: s3 bucket used to store data needed by the stack
        :param s3_key: s3 prefix in s3_bucket in which data is stored
        """
        assert (
            re.match(VALID_STACK_NAME, name) and len(name) <= VALID_STACK_NAME_MAX_LEN
        ), ("invalid stack name: %s" % name)
        self.resources: dict[str, Resource | Stack] = {}
        self.name = name

        # In most cfn calls name and id can be used for StackName parameter. On first
        # call to state the real stack_id will be stored in self.stack_id ensuring
        # that the stack can be still refered to even when operation like delete are
        # used.
        self.stack_id = name
        self.description = description
        self.s3_bucket = s3_bucket
        self.s3_key = s3_key

        # Emit a warning to the user if no role is passed for Cloud Formation
        if cfn_role_arn is None:
            logging.warning(
                "Consider using a separate role for CloudFormation to "
                "reduce permissions needed by the entity in charge of "
                "deploying the stack (see Stack cfn_role_arn parameter)"
            )
        self.cfn_role_arn = cfn_role_arn
        self.creation_date = datetime.now().timestamp()

        # The uuid is used by create and create_change_set. It allows then
        # to track for example events associated with that deployment
        self.uuid = str(uuid.uuid1(clock_seq=int(1000 * time.time())))
        self.latest_read_event: Optional[StackEvent] = None

    def add(self, element: Stack | Resource) -> Stack:
        """Add a resource or merge a stack.

        :param element: if a resource add the resource to the stack. If a stack
            merge its resources into the current stack.
        :return: the current stack
        """
        assert isinstance(element, Resource) or isinstance(element, Stack), (
            "a resource or a stack is expected. got %s" % element
        )
        assert element.name not in self.resources, (
            "resource already exist: %s" % element.name
        )
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

    def create_data_dir(self, root_dir: str) -> None:
        """Populate directory that will be exported into a S3 bucket for the stack.

        :param root_dir: temporary local directory
        """
        for resource in self.resources.values():
            resource.create_data_dir(root_dir)

    def export(self) -> dict:
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
                stack_resources = resource.export()["Resources"]
                for k, v in stack_resources.items():
                    assert k not in resources
                    resources[k] = v

        result = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}
        if self.description is not None:
            result["Description"] = self.description
        return result

    @property
    def body(self) -> str:
        """Export stack as a CloudFormation template.

        :return: a valid CloudFormation template
        :rtype: str
        """
        return yaml.dump(self.export(), Dumper=CFNYamlDumper)

    @client("cloudformation")
    def create(
        self,
        client: botocore.client.Client,
        url: Optional[str] = None,
        wait: bool = False,
    ) -> None:
        """Create a stack.

        :param client: a botocore client
        param url: url of the template body in S3. When not None this suppose
            the user has uploaded the template body on S3 first at the given
            url. Use S3 to refer to the template body rather than using inline
            version allows to use template of size up to 500Ko instead of
            50Ko.
        :param wait: if True wait for creation completion
        """
        parameters = {
            "StackName": self.name,
            "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        }

        if url is None:
            parameters["TemplateBody"] = self.body
        else:
            parameters["TemplateURL"] = url

        if self.cfn_role_arn is not None:
            parameters["RoleARN"] = self.cfn_role_arn

        parameters["ClientRequestToken"] = self.uuid
        client.create_stack(**parameters)

        if wait:
            logging.info("Waiting for stack creation...")
            logging.info(f"Done (status: {self.wait()})")

    @client("cloudformation")
    def wait(self, client: botocore.client.Client) -> str:
        status = self.state()
        while "PROGRESS" in status["StackStatus"]:
            for event in self.events(mark_as_read=True):
                logging.info(str(event))
            time.sleep(5.0)
            status = self.state()

        # Get last eents
        for event in self.events(mark_as_read=True):
            logging.info(str(event))
        return status["StackStatus"]

    def exists(self) -> bool:
        """Check if a given stack exists.

        :return: True if it does, False otherwise
        """
        try:
            self.state()
            return True
        except Exception:
            # Documentation does not specify the right exception that is raised
            # by botocore.
            return False

    @client("cloudformation")
    def state(self, client):
        """Return state of the stack on AWS."""
        result = client.describe_stacks(StackName=self.stack_id)["Stacks"][0]
        if self.stack_id != result["StackId"]:
            self.stack_id = result["StackId"]
        return result

    @client("cloudformation")
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

    @client("cloudformation")
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
                Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            )
        else:
            return client.create_change_set(
                ChangeSetName=name,
                StackName=self.name,
                TemplateURL=url,
                Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            )

    @client("cloudformation")
    def describe_change_set(self, name, client):
        """Describe a change set.

        Retrieve status of a given changeset

        :param client: a botocore client
        :type client: botocore.client.Client
        :param name: name of the changeset
        :type name: str
        """
        return client.describe_change_set(ChangeSetName=name, StackName=self.name)

    @client("cloudformation")
    def delete_change_set(self, name, client):
        """Delete a change set.

        :param client: a botocore client
        :type client: botocore.client.Client
        :param name: name of the changeset
        :type name: str
        """
        return client.delete_change_set(ChangeSetName=name, StackName=self.name)

    @client("cloudformation")
    def delete(self, client: botocore.client.Client, wait: bool = False) -> None:
        """Delete a stack.

        Delete a stack. Note that operation is aynchron

        :param client: a botocore client
        :type client: botocore.client.Client
        :param wait: if True wait for complete deletion
        """
        # Ensure to fill stack_id
        try:
            self.state()
        except Exception:
            logging.error(f"Stack {self.name} does not exist")
            return

        client.delete_stack(StackName=self.name, ClientRequestToken=self.uuid)
        if wait:
            logging.info("Wait for stack deletion")
            logging.info(f"Done (status: {self.wait()})")

    @client("cloudformation")
    def events(
        self,
        client: botocore.client.BaseClient,
        failed_only: bool = False,
        mark_as_read: bool = True,
    ) -> Iterator[StackEvent]:
        """Return non read events.

        :param failed_only: return only failed events
        :param mark_as_read: if True, all events read won't be returned on next
            calls to events method.
        """
        from e3.aws import iterate

        latest_read_event = self.latest_read_event
        if mark_as_read:
            self.latest_read_event = None

        for element in iterate(
            client.describe_stack_events, key="StackEvents", StackName=self.stack_id
        ):
            event = StackEvent.from_dict(element)

            # Update marker for last event read
            if mark_as_read and self.latest_read_event is None:
                self.latest_read_event = event

            if event.client_token != self.uuid:
                # Event is not associated with current operations. Skip
                continue
            elif (
                latest_read_event is not None
                and latest_read_event.timestamp == event.timestamp
            ):
                # Event is already read so stop iterating.
                break
            elif failed_only and event.resource_status != StackEventState.failed:
                continue
            else:
                yield event

    @client("cloudformation")
    def cost(self, client):
        """Compute cost of the stack (estimation).

        :param client: a botocore client
        :type client: botocore.client.BaseClient
        """
        return client.estimate_template_cost(TemplateBody=self.body)

    @client("cloudformation")
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
            StackName=self.name,
            ClientRequestToken=self.uuid,
        )

        if wait:
            logging.info("Waiting for stack update...")
            logging.info(f"Done (status: {self.wait()})")

    @client("cloudformation")
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
        assert "StackResources" in aws_result
        result = {}
        for res in aws_result["StackResources"]:
            if "PROGRESS" in res["ResourceStatus"] or not in_progress_only:
                result[res["LogicalResourceId"]] = res["ResourceStatus"]
        return result

    @client("cloudformation")
    def enable_termination_protection(self, client):
        """Enable termination protection for a stack."""
        aws_result = self.state()
        if aws_result["EnableTerminationProtection"]:
            print("Stack termination protection is already enabled")
            return

        aws_result = client.update_termination_protection(
            EnableTerminationProtection=True, StackName=self.name
        )
        assert "StackId" in aws_result
        print("Stack termination protection enabled")

    @client("cloudformation")
    def set_stack_policy(self, stack_policy_body, client):
        """Set a stack policy.

        :param stack_policy_body: stack policy body to apply
        :type stack_policy_body: str
        """
        aws_result = client.get_stack_policy(StackName=self.name)

        if stack_policy_body != aws_result["StackPolicyBody"]:
            print("Stack policy has been modified")

            client.set_stack_policy(
                StackName=self.name, StackPolicyBody=stack_policy_body
            )
        else:
            print("Stack policy already up-to-date")
