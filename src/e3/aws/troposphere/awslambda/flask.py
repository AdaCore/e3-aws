"""Ease deployment of a lambda used in API Gateway using Flask framework.

For example if you have app.py in /myapp directory::

    from flask import Flask
    app = Flask(__name__)

    @app.route('/')
    def hello_world():
        return 'Hello, World!'

You can create the associated lambda by adding the following element in your
stack::

    lambda_function = Py38FlaskFunction(name="myapp",
                                        description="a comment",
                                        role=lambda_role,
                                        code_dir="/myapp",
                                        app="app.app")
    stack.add(lambda_function)

The resulting lambda can then be added into an HttpAPI::

    stack.add(HttpApi(name="myapi",
                      description="my api description",
                      lambda_arn=lambda_function.arn,
                      route_list=[Get("/")]))

"""
from __future__ import annotations
from typing import TYPE_CHECKING
import os

from troposphere import GetAtt
from e3.aws.troposphere.iam.role import Role
from e3.fs import cp, sync_tree
from . import Py38Function

if TYPE_CHECKING:
    from typing import Optional

STARTUP_CODE = """
from %(app_module)s import %(app_name)s
from flask_apigateway2_http_wrapper import FlaskLambdaHandler

lambda_handler = FlaskLambdaHandler(%(app_name)s)
lambda_handler_fun = lambda_handler.lambda_handler
"""


class Py38FlaskFunction(Py38Function):
    def __init__(
        self,
        name: str,
        description: str,
        role: str | GetAtt | Role,
        code_dir: str,
        app: str,
        requirement_file: Optional[str] = None,
        code_version: Optional[int] = None,
        timeout: int = 3,
        memory_size: Optional[int] = None,
    ):
        """Initialize an AWS lambda function using Python 3.8 runtime.

        :param name: function name
        :param description: a description of the function
        :param role: role to be asssumed during lambda execution
        :param code_dir: directory containing the python code
        :param app: Flask app symbol name
        :param requirement_file: requirement file for the application code.
            Required packages are automatically fetched (works only from linux)
            and packaged along with the lambda code
        :param code_version: code version
        :param timeout: maximum execution time (default: 3s)
        :param memory_size: the amount of memory available to the function at
            runtime. The value can be any multiple of 1 MB.
        """
        self.app_module, self.app_name = app.rsplit(".", 1)

        super().__init__(
            name=name,
            description=description,
            role=role,
            code_dir=code_dir,
            handler="lambda_handler_module.lambda_handler_fun",
            requirement_file=requirement_file,
            code_version=code_version,
            timeout=timeout,
            memory_size=memory_size,
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
            "flask_apigateway2_http_wrapper.py",
        )
        cp(wrapper_file, package_dir)
        sync_tree(package_dir, "/tmp/nico/package")
