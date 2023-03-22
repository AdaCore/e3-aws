"""Ease deployment of a lambda used in API Gateway using Flask framework.

For example if you have app.py in /myapp directory::

    from flask import Flask
    app = Flask(__name__)

    @app.route('/')
    def hello_world():
        return 'Hello, World!'

You can create the associated lambda by adding the following element in your
stack::

    lambda_function = PyFlaskFunction(name="myapp",
                                      description="a comment",
                                      role=lambda_role,
                                      code_dir="/myapp",
                                      app="app.app",
                                      runtime="python3.9")
    stack.add(lambda_function)

The resulting lambda can then be added into an HttpAPI::

    stack.add(HttpApi(name="myapi",
                      description="my api description",
                      lambda_arn=lambda_function.arn,
                      route_list=[Get("/")]))

"""
from __future__ import annotations
import os

from troposphere import GetAtt
from e3.aws.troposphere.iam.role import Role
from e3.fs import cp, sync_tree
from . import PyFunction


STARTUP_CODE = """
from %(app_module)s import %(app_name)s
from flask_apigateway_wrapper import FlaskLambdaHandler

lambda_handler = FlaskLambdaHandler(%(app_name)s)
lambda_handler_fun = lambda_handler.lambda_handler
"""


class PyFlaskFunction(PyFunction):
    """Provide PyFlaskFunction Construct."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        code_dir: str,
        app: str,
        runtime: str,
        requirement_file: str | None = None,
        code_version: int | None = None,
        timeout: int = 3,
        memory_size: int | None = None,
        logs_retention_in_days: int | None = 731,
        reserved_concurrent_executions: int | None = None,
        environment: dict[str, str] | None = None,
    ):
        """Initialize a Flask AWS lambda function using a Python runtime.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param code_dir: directory containing the python code
        :param app: Flask app symbol name
        :param runtime: lambda runtime. It must be a Python runtime.
        :param requirement_file: requirement file for the application code.
            Required packages are automatically fetched (works only from linux)
            and packaged along with the lambda code
        :param code_version: code version
        :param timeout: maximum execution time (default: 3s)
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        :param logs_retention_in_days: The number of days to retain the log events
            in the lambda log group
        :param reserved_concurrent_executions: The number of concurrent executions
            that are reserved for this function
        :param environment: Environment variables that are accessible from function
            code during execution
        """
        self.app_module, self.app_name = app.rsplit(".", 1)

        super().__init__(
            name=name,
            description=description,
            role=role,
            code_dir=code_dir,
            handler="lambda_handler_module.lambda_handler_fun",
            runtime=runtime,
            requirement_file=requirement_file,
            code_version=code_version,
            timeout=timeout,
            memory_size=memory_size,
            logs_retention_in_days=logs_retention_in_days,
            reserved_concurrent_executions=reserved_concurrent_executions,
            environment=environment,
        )

    def populate_package_dir(self, package_dir: str) -> None:
        super().populate_package_dir(package_dir=package_dir)

        handler_file = os.path.join(package_dir, "lambda_handler_module.py")
        with open(handler_file, "w") as fd:
            fd.write(
                STARTUP_CODE
                % {"app_module": self.app_module, "app_name": self.app_name}
            )
        wrapper_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "flask_apigateway_wrapper.py",
        )
        cp(wrapper_file, package_dir)
        sync_tree(package_dir, "/tmp/nico/package")


class Py38FlaskFunction(PyFlaskFunction):
    """Provide Py38FlaskFunction Construct."""

    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        code_dir: str,
        app: str,
        requirement_file: str | None = None,
        code_version: int | None = None,
        timeout: int = 3,
        memory_size: int | None = None,
        logs_retention_in_days: int | None = None,
    ):
        """Initialize a Flask AWS lambda function using Python 3.8 runtime.

        For params see PyFlaskFunction.
        """
        super().__init__(
            name=name,
            description=description,
            role=role,
            code_dir=code_dir,
            app=app,
            runtime="python3.8",
            requirement_file=requirement_file,
            code_version=code_version,
            timeout=timeout,
            memory_size=memory_size,
            logs_retention_in_days=logs_retention_in_days,
        )
