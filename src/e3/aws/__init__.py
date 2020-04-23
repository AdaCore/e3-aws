import argparse
import botocore.session
import json
from botocore.stub import Stubber
from uuid import uuid4

from e3.env import Env


class Session(object):
    """Handle AWS session and clients."""

    def __init__(self, regions=None, stub=False, profile=None, credentials=None):
        """Initialize an AWS session.

        Once intialized AWS environment can be accessed from Env().aws_env

        :param regions: list of regions to work on. The first region is
            considered as the default region.
        :type regions: list[str]
        :param stub: if True clients are necessarily stubbed
        :type stub: bool
        :param profile: profile name
        :type profile: str | None
        :param credentials: AWS credentials dictionary containing the
            following keys: AccessKeyId, SecretAccessKey, SessionToken
            as returnedy by ``assume_role``
        :type credentials: dict[str]
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
            self.regions = [self.session.region_name]
        else:
            self.regions = regions
        self.default_region = None
        self.force_stub = stub
        self.clients = {}
        self.stubbers = {}

        self._account_alias = None

    def assume_role(self, role_arn, role_session_name):
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
        self, role_arn, role_session_name, session_duration=None
    ):
        """Return credentials for ``role_arn``.

        :param role_arn: ARN of the role to assume
        :type role_arn: str
        :param role_session_name: a name to associate with the created
            session
        :type role_session_name: str
        :param session_duration: session duration in seconds or None for
            default
        :type session_duration: int | None
        :return: credentials dictionary
        :rtype: dict
        """
        client = self.client("sts", region=self.regions[0])
        arguments = {"RoleArn": role_arn, "RoleSessionName": role_session_name}
        if session_duration is not None:
            arguments["DurationSeconds"] = session_duration

        response = client.assume_role(**arguments)
        return response["Credentials"]

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
