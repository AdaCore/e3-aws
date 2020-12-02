from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
import argparse
import botocore.session
import json
import logging
import os
import re
import time

from botocore.exceptions import ClientError
from botocore.stub import Stubber
from uuid import uuid4
from troposphere import AWSObject, Template

from e3.env import Env

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional
    from botocore.client import BaseClient


class Session(object):
    """Handle AWS session and clients."""

    def __init__(
        self,
        regions: Optional[List] = None,
        stub: bool = False,
        profile: Optional[str] = None,
        credentials: Optional[Dict] = None,
    ) -> None:
        """Initialize an AWS session.

        Once initialized AWS environment can be accessed from Env().aws_env

        :param regions: list of regions to work on. The first region is
            considered as the default region. This parameter should be provided
            if AWS environment variables are not used to specified the region
        :param stub: if True clients are necessarily stubbed
        :param profile: profile name
        :param credentials: AWS credentials dictionary containing the
            following keys: AccessKeyId, SecretAccessKey, SessionToken
            as returned by ``assume_role``
        """
        if profile is not None or credentials is None:
            self.session = botocore.session.Session(profile=profile)
        else:
            self.session = botocore.session.Session()
            self.session.set_credentials(
                access_key=credentials["AccessKeyId"],
                secret_key=credentials["SecretAccessKey"],
                token=credentials["SessionToken"],
            )

        self.profile = profile
        if regions is None:
            # the value return below is ('region', 'AWS_DEFAULT_REGION', None, None)
            # See botocore/configprovider.py
            region_variable = self.session.SESSION_VARIABLES["region"][1]
            region = os.environ.get(region_variable, "")
            if not region:
                raise ValueError(
                    "region should be specified either using regions "
                    "parameter or using AWS environment variables"
                )
            self.regions = [region]
        else:
            self.regions = regions

        self.default_region = self.regions[0]

        self.force_stub = stub
        self.clients = {}
        self.stubbers = {}

        self._account_alias = None

        self._identity = None

    def assume_role(self, role_arn: str, role_session_name: str) -> Session:
        """Return a session with ``role_arn`` credentials.

        :param role_arn: ARN of the role to assume
        :type role_arn: str
        :param role_session_name: a name to associate with the created
            session
        :type role_session_name: str

        :return: a Session instance
        :rtype: Session
        """
        credentials = self.assume_role_get_credentials(role_arn, role_session_name)
        return Session(regions=self.regions, credentials=credentials)

    def assume_role_get_credentials(
        self,
        role_arn: str,
        role_session_name: str,
        session_duration: Optional[int] = None,
        as_env_var: bool = False,
    ) -> Dict[str]:
        """Return credentials for ``role_arn``.

        :param role_arn: ARN of the role to assume
        :param role_session_name: a name to associate with the created
            session
        :param session_duration: session duration in seconds or None for
            default
        :param as_env_var: if set to True the returned credentials dictionnary
            keys are translated to be compatible to update os.environ.
        """
        client = self.client("sts", region=self.regions[0])
        arguments = {"RoleArn": role_arn, "RoleSessionName": role_session_name}
        if session_duration is not None:
            arguments["DurationSeconds"] = session_duration

        response = client.assume_role(**arguments)

        credentials = response["Credentials"]
        if as_env_var:
            key_to_envvar = {
                "AccessKeyId": "AWS_ACCESS_KEY_ID",
                "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
                "SessionToken": "AWS_SESSION_TOKEN",
            }
            credentials = {
                key_to_envvar[k]: v
                for k, v in credentials.items()
                if k in key_to_envvar
            }

        return credentials

    @property
    def account_alias(self):
        """Return current account alias."""
        if self._account_alias is None:
            client = self.client("iam", region="us-east-1")
            aliases = client.list_account_aliases()["AccountAliases"]
            if aliases:
                # Even if the API return a list there currently only one
                # alias possible
                self._account_alias = aliases[0]
            else:
                self._account_alias = ""
        return self._account_alias

    @property
    def identity(self):
        """Return identity information."""
        if self._identity is None:
            sts_client = self.client("sts")
            self._identity = {"UserId": "", "Account": "", "Arn": ""}
            self._identity.update(sts_client.get_caller_identity())

        return self._identity

    def stub(self, name, region=None):
        """Return stub for a given client.

        Note that if the client does not exist yet it will be created.

        :param name: client name
        :type name: str
        :param region: region associated with the client. If None the default
            region is taken.
        :type region: str | None
        :return: the stub instance
        :rtype: botocore.stub.Stubber
        """
        if not self.force_stub:
            return None
        if region is None:
            region = self.default_region

        if name not in self.stubbers or region not in self.stubbers[name]:
            # Create client
            self.client(name, region)

        return self.stubbers[name][region]

    def client(self, name, region=None):
        """Get a client.

        :param name: client name
        :type name: str
        :param region: region associated with the client. If None the default
            region is taken.
        :type region: str | None
        :return: a client instance
        :rtype: botocore.Client
        """
        if region is None:
            region = self.default_region

        assert region is not None, "no region or default_region set"

        if name not in self.clients:
            self.clients[name] = {}
            self.stubbers[name] = {}

        if region not in self.clients[name]:
            self.clients[name][region] = self.session.create_client(
                name, region_name=region
            )
            if self.force_stub:
                self.stubbers[name][region] = Stubber(self.clients[name][region])
                self.stubbers[name][region].activate()

        return self.clients[name][region]


class AWSEnv(Session):
    """Handle AWS session and clients."""

    def __init__(self, regions=None, stub=False, profile=None):
        """Initialize an AWS session.

        Once intialized AWS environment can be accessed from Env().aws_env

        :param regions: list of regions to work on. The first region is
            considered as the default region.
        :type regions: list[str]
        :param stub: if True clients are necessarily stubbed
        :type stub: bool
        :param profile: profile name
        :type profile: str | None
        """
        super().__init__(regions=regions, stub=stub, profile=profile)
        env = Env()
        env.aws_env = self


class default_region(object):
    """Context manager used to set a default region."""

    def __init__(self, region):
        """Initialize context manager.

        :param region: default region
        :type region: str
        """
        aws_env = Env().aws_env

        self.previous_region = aws_env.default_region
        self.default_region = region

    def __enter__(self):
        Env().aws_env.default_region = self.default_region

    def __exit__(self, _type, _value, _tb):
        del _type, _value, _tb
        Env().aws_env.default_region = self.previous_region


def client(name):
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


def session():
    """Decorate a function to handle automatically AWS session retrieval.

    The function in input should take a mandatory argument called session.

    :param name: session name
    :type name: str
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            if "session" in kwargs:
                session = kwargs.get("session")
                del kwargs["session"]
            else:
                session = Env().aws_env
            return func(*args, session=session, **kwargs)

        return wrapper

    return decorator


def assume_role_main():
    """Generate shell commands to set credentials for a role."""
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        "--json", action="store_true", help="Output credentials as JSON"
    )
    argument_parser.add_argument(
        "--role-session-name",
        help="Role session name, by default a random value is generated",
    )
    argument_parser.add_argument("--session-duration")
    argument_parser.add_argument("role_arn")
    args = argument_parser.parse_args()

    key_to_envvar = {
        "AccessKeyId": "AWS_ACCESS_KEY_ID",
        "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
        "SessionToken": "AWS_SESSION_TOKEN",
    }

    s = Session(regions=["eu-west-1"])
    session_duration = args.session_duration
    if session_duration is not None:
        session_duration = int(session_duration)

    if args.role_session_name:
        role_session_name = args.role_session_name
    else:
        role_session_name = str(uuid4()).replace("-", "")

    credentials = s.assume_role_get_credentials(
        args.role_arn, role_session_name, session_duration=session_duration
    )
    credentials["Expiration"] = credentials["Expiration"].timestamp()
    if args.json:
        print(json.dumps(credentials))
    else:
        credentials = {
            key_to_envvar[k]: v for k, v in credentials.items() if k in key_to_envvar
        }
        for k, v in credentials.items():
            print(f"export {k}={v}")


def iterate(fun, key, **kwargs):
    """Create an iterator other paginate botocore function.

    :param fun: the function to call
    :type fun: fun
    :param key: the key in the returned data containing the elements
    :type key: str
    :param kwargs: parameters passed to the function
    :type kwargs: dict
    """
    result = fun(**kwargs)
    for data in result.get(key, []):
        yield data

    while result.get("NextToken"):
        result = fun(NextToken=result["NextToken"], **kwargs)
        for data in result.get(key, []):
            yield data


class Property(ABC):
    """Property abstract class.

    Define an intermediate class that can be used to build a Construct.
    Construct use property by accessing their as_dict attribute that should
    correspond to a valid troposphere property definition.
    """

    @property
    @abstractmethod
    def as_dict(self) -> dict:
        """Return dictionary representation of the property."""
        pass


class Construct(ABC):
    """Represent one or multiple troposphere AWSObject.

    AWSObjects are accessible with aws_object attribute.
    """

    @property
    @abstractmethod
    def aws_objects(self) -> List[AWSObject]:
        """Return a list of troposphere AWSObject.

        Objects returned can be added to a troposphere template with
        add_resource Template method.
        """
        pass


class Stack:
    """High level class to build and deploy a CloudFormation stack."""

    def __init__(
        self, stack_name: str, session: Session, opts: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize Stack attributes.

        :param stack_name: name of the stack to deploy
        :param session: AWS session
        :param opts: boto3 option for CloudFormation stack deployment
            (see CloudFormation.Client.create_stack)
        """
        self.name = stack_name
        self.session = session
        self._client = None
        self.opts = opts
        self.template: Template = Template()

    def __getitem__(self, resource_name: str) -> AWSObject:
        """Return AWSObject associated with resource_name.

        :param resource_name: name of the resource to retrieve
        """
        return self.template.resources[name_to_id(resource_name)]

    @property
    def client(self) -> BaseClient:
        """Return botocore client for Cloudformation."""
        if not self._client:
            self._client = self.session.client("cloudformation")
        return self._client

    def __stack_status(self) -> Dict[str, Any]:
        """Return stack status information.

        :return: stack status information
            (see boto3 documentation CloudFormation.Client.describe_stacks)
        """
        response = self.client.describe_stacks(StackName=self.name)
        return response["Stacks"][0]

    def add_resource(self, obj: AWSObject) -> None:
        """Add a troposphere AWSObject to self template.

        :param obj: object to add to the template
        """
        self.template.add_resource(obj)

    def add_construct(self, aws_constructs: List[Construct]) -> None:
        """Add resources associated to Construct instances to a troposphere template.

        :param aws_constructs: list of constructs from which associated AWSObject
            are added to template
        """
        for construct in aws_constructs:
            construct_objects = construct.aws_objects
            for obj in construct_objects:
                logger.debug(f"Adding {obj.title} to template {self.name}")
                self.add_resource(obj)

    def deploy(self) -> None:
        """Deploy stack by creating or updating it if it already exists."""
        logger.info(f"Deploying stack {self.name}")
        logger.info(f"With template:\n {self.template.to_json()}")
        kwargs = {"StackName": self.name, "TemplateBody": self.template.to_json()}
        if self.opts:
            kwargs.update(self.opts)

        try:
            logging.info(f"Creating stack: {self.name}")
            self.client.create_stack(**kwargs)
        except ClientError as boto_exception:
            if boto_exception.response["Error"]["Code"] == "AlreadyExistsException":
                logging.info(f"Updating already existing stack: {self.name}")
                self.client.update_stack(**kwargs)
            else:
                raise boto_exception

    def undeploy(self) -> None:
        """Undeploy stack."""
        logger.info(f"Undeploying stack {self.name}")
        # ??? probably we should look before if the stack exists
        self.client.delete_stack(StackName=self.name)
        status = ""
        while True:
            try:
                status_info = self.__stack_status()
                status = status_info["StackStatus"]
                logger.info(f"Status : {status}")
            except ClientError as boto_exception:
                if boto_exception.response["Error"]["Code"] == "ValidationError":
                    logger.info("Delete successful")
                    break
                else:
                    raise boto_exception

            if status == "DELETE_FAILED":
                logger.info("Undeploy failed")
                break
            time.sleep(2)


def name_to_id(name: str) -> str:
    """Convert a resource name to a resource id.

    The conversion is done by removing characters that are not alphanumeric as
    resource id must contain only alphanumeric character and first character and
    characters following a dash to uppercase for a better readability.
    """

    def replacement(match):
        """Return uppercased second character of the match."""
        return match.group(1)[1].upper()

    resource_id = re.sub(r"[^a-zA-Z0-9]", "", re.sub(r"(-[a-z])", replacement, name))
    resource_id = resource_id[0].upper() + resource_id[1:]
    return resource_id
