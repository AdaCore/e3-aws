from __future__ import absolute_import, division, print_function
from botocore.stub import Stubber
from e3.env import Env
import botocore.session


class AWSEnv(object):
    """Handle AWS session and clients."""

    def __init__(self, regions=None, stub=False):
        """Initialize an AWS session.

        Once intialized AWS environment can be accessed from Env().aws_env

        :param regions: list of regions to work on. The first region is
            considered as the default region.
        :type regions: list[str]
        :param stub: if True clients are necessarily stubbed
        :type stub: bool
        """
        self.session = botocore.session.get_session()
        if regions is None:
            self.regions = [self.session.region_name]
        else:
            self.regions = regions
        self.default_region = None
        self.force_stub = stub
        self.clients = {}
        self.stubbers = {}
        env = Env()
        env.aws_env = self

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

        assert region is not None, 'no region or default_region set'

        if name not in self.clients:
            self.clients[name] = {}
            self.stubbers[name] = {}

        if region not in self.clients[name]:
            self.clients[name][region] = \
                self.session.create_client(name, region_name=region)
            if self.force_stub:
                self.stubbers[name][region] = \
                    Stubber(self.clients[name][region])
                self.stubbers[name][region].activate()

        return self.clients[name][region]


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
            if 'region' in kwargs:
                region = kwargs['region']
                del kwargs['region']
            else:
                region = aws_env.default_region
            client = aws_env.client(name, region=region)
            return func(*args, client=client, **kwargs)
        return wrapper
    return decorator
