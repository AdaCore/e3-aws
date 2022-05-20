from __future__ import annotations
from typing import TYPE_CHECKING
import argparse
import boto3
import botocore.session
import json
import logging
import os
import re
import requests
import requests.auth
import urllib.parse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.stub import Stubber
from uuid import uuid4


from e3.error import E3Error
from e3.env import Env
from e3.os.process import Run

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional, Callable
    import botocore.client
    import botocore.stub


class AWSSessionRunError(E3Error):
    def __init__(
        self, message: str, origin: str, process: Optional[Run] = None
    ) -> None:
        """Initialize an AWSSessionRunError.

        :param message: the exception message
        :param origin: the name of the function, class, or module having raised
        :param process: process that failed
        """
        super().__init__(message, origin)
        self.origin = origin
        self.message = message
        self.process = process


class Session:
    """Handle AWS session and clients."""

    def __init__(
        self,
        regions: Optional[list[str]] = None,
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
        self.clients: dict[str, botocore.client.Client] = {}
        self.stubbers: dict[str, botocore.stub.Stubber] = {}

        self._account_alias = None

        self._identity = None

    def assume_role(
        self,
        role_arn: str,
        role_session_name: str,
        session_duration: Optional[int] = None,
    ) -> Session:
        """Return a session with ``role_arn`` credentials.

        :param role_arn: ARN of the role to assume
        :param role_session_name: a name to associate with the created
            session
        :param session_duration: session duration in seconds or None for
            default
        :return: a Session instance
        :rtype: Session
        """
        credentials = self.assume_role_get_credentials(
            role_arn, role_session_name, session_duration=session_duration
        )
        return Session(regions=self.regions, credentials=credentials)

    def assume_role_get_credentials(
        self,
        role_arn: str,
        role_session_name: str,
        session_duration: Optional[int] = None,
        as_env_var: bool = False,
    ) -> Dict[str, Any]:
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
        arguments: Dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": role_session_name,
        }
        if session_duration is not None:
            arguments["DurationSeconds"] = session_duration

        # If AWS_MFA_DEVICE is in the environment ask user for OTP
        if "AWS_MFA_DEVICE" in os.environ:  # all: no cover
            arguments["SerialNumber"] = os.environ["AWS_MFA_DEVICE"]
            otp = input("Enter MFA code: ")
            arguments["TokenCode"] = otp

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

    def stub(self, name: str, region: Optional[str] = None) -> botocore.stub.Stubber:
        """Return stub for a given client.

        Note that if the client does not exist yet it will be created.

        :param name: client name
        :param region: region associated with the client. If None the default
            region is taken.
        :return: the stub instance
        """
        if not self.force_stub:
            return None
        if region is None:
            region = self.default_region

        if name not in self.stubbers or region not in self.stubbers[name]:
            # Create client
            self.client(name, region)

        return self.stubbers[name][region]

    def to_boto3(self) -> boto3.Session:
        """Return boto3 session initialized from current botocore session."""
        credentials = self.session.get_credentials()
        frozen_credentials = credentials.get_frozen_credentials()
        return boto3.Session(
            aws_access_key_id=frozen_credentials.access_key,
            aws_secret_access_key=frozen_credentials.secret_key,
            aws_session_token=frozen_credentials.token,
            region_name=self.default_region,
            profile_name=self.profile,
        )

    def client(self, name: str, region: Optional[str] = None) -> botocore.client.Client:
        """Get a client.

        :param name: client name
        :param region: region associated with the client. If None the default
            region is taken.
        :return: a client instance
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

    def run(
        self, cmd: List[str], role_arn: str, session_duration: int, **kwargs: Any
    ) -> Run:
        """Execute a command with credentials to assume role role_arn.

        :param cmd: command to execute
        :role_arn: Arn of the role to be used by the command
        :session_duration: session duration in seconds or None for default
        :param kwargs: additional parameters to provide to e3.os.process.Run
        :return: Result of the call to Run for the command
        """
        credentials = self.assume_role_get_credentials(
            role_arn, "aws_run_session", session_duration, as_env_var=True
        )

        if "env" not in kwargs:
            if "ignore_environ" not in kwargs:
                kwargs["ignore_environ"] = False
            kwargs["env"] = credentials
        else:
            kwargs["env"] = dict(kwargs["env"]).update(credentials)

        aws_p = Run(cmd, **kwargs)

        if aws_p.status:
            raise AWSSessionRunError(
                f"{cmd} failed (exit status: {aws_p.status})",
                origin="aws_session_cli_cmd",
                process=aws_p,
            )
        return aws_p


class AWSEnv(Session):
    """Handle AWS session and clients."""

    def __init__(
        self,
        regions: Optional[list[str]] = None,
        stub: bool = False,
        profile: Optional[str] = None,
    ):
        """Initialize an AWS session.

        Once intialized AWS environment can be accessed from Env().aws_env

        :param regions: list of regions to work on. The first region is
            considered as the default region.
        :param stub: if True clients are necessarily stubbed
        :param profile: profile name
        """
        super().__init__(regions=regions, stub=stub, profile=profile)
        env = Env()
        env.aws_env = self


class default_region:
    """Context manager used to set a default region."""

    def __init__(self, region: str):
        """Initialize context manager.

        :param region: default region
        """
        aws_env = Env().aws_env

        self.previous_region = aws_env.default_region
        self.default_region = region

    def __enter__(self):
        Env().aws_env.default_region = self.default_region

    def __exit__(self, _type, _value, _tb):
        del _type, _value, _tb
        Env().aws_env.default_region = self.previous_region


def session() -> Callable:
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


def iterate(fun: Callable, key: str, **kwargs: Any) -> Any:
    """Create an iterator other paginate botocore function.

    :param fun: the function to call
    :param key: the key in the returned data containing the elements
    :param kwargs: parameters passed to the function
    """
    result = fun(**kwargs)
    for data in result.get(key, []):
        yield data

    while result.get("NextToken"):
        result = fun(NextToken=result["NextToken"], **kwargs)
        for data in result.get(key, []):
            yield data


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


class IAMAuth(requests.auth.AuthBase):
    """Authorizer for the requests framework that use AWS Signature V4 protocol."""

    def __init__(
        self, session: Session, role: Optional[str] = None, region: Optional[str] = None
    ):
        """Initialize authorizer.

        :param session: an aws session
        :param role: if not None role to assume
        :param region: if None use default region (from session) otherwise use it as
            region
        """
        self.session = session
        self.role = role
        if region is None:
            self.region = self.session.default_region
        else:
            self.region = region

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """See requests framework."""
        # The code does not implement the signature v4 protocol. It reuses parts of
        # botocore to do so. Botocore does not provide a generic interface to sign
        # a given request. So the following code create a temporary AWSRequest object
        # with the same parameters as the user request, sign it and then extract
        # the signature (i.e: the headers) that is re-injected into the user request.
        session = self.session
        if self.role is not None:
            session = self.session.assume_role(self.role, "iamauthsession")

        credentials = session.session.get_credentials().get_frozen_credentials()

        # Split back the url in order to be able to call AWSRequest
        aws_headers = dict(request.headers)
        key_to_delete = []
        for key in aws_headers:
            if key.lower() in ("accept", "accept-encoding", "connection"):
                key_to_delete.append(key)

        for key in key_to_delete:
            del aws_headers[key]

        parsed_url = urllib.parse.urlparse(request.url)
        aws_params = {
            str(k): ",".join(v)
            for k, v in urllib.parse.parse_qs(str(parsed_url.query)).items()
        }
        aws_url = urllib.parse.urlunparse(
            (
                str(parsed_url.scheme),
                str(parsed_url.netloc),
                str(parsed_url.path),
                str(parsed_url.params),
                "",
                "",
            )
        )

        # Compute the headers for the request
        aws_request = AWSRequest(
            method=request.method, url=aws_url, params=aws_params, headers=aws_headers
        )
        SigV4Auth(credentials, "execute-api", self.region).add_auth(aws_request)

        # Update request headers
        request.headers.update(aws_request.headers)
        return request
