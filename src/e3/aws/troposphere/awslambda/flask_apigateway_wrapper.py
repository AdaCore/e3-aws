# The following package is packaged automatically with Flask lambda.
# Do not introduce dependencies outside Python standard library.
from __future__ import annotations
from typing import TYPE_CHECKING
import json
import io
import sys
import base64
from urllib.parse import urlencode

if TYPE_CHECKING:
    from typing import Any


class FlaskLambdaHandler:
    """Flask lambda handler."""

    def __init__(self, app: Any) -> None:
        """Initialize a Flask lambda handler.

        :param app: a Flask app
        """
        self.app = app
        self.status = None
        self.response_headers = None

    def start_response(self, status, response_headers, exc_info=None):
        """Implement Flask callback to store the response.

        See Flask documentation.
        """
        self.status = int(status[:3])
        self.response_headers = dict(response_headers)

    def lambda_handler(self, event, context):
        """Lambda entry point."""
        self.status = None
        self.response_headers = None

        body = next(
            self.app.wsgi_app(
                self.create_flask_wsgi_environ(event, context), self.start_response
            )
        )
        return {
            "statusCode": self.status,
            "headers": self.response_headers,
            "body": body,
        }

    def create_flask_wsgi_environ(self, event: dict, context: dict) -> dict:
        """Create a WSGI environment from AWS lambda input.

        Currently this function supports creation of WSGI environment from
        API Gateway HTTP API 2.0 and a REST API

        :param event: as received by the lambda
        :param context: as received by the lambda
        """
        request_ctx = event["requestContext"]
        remote_user: str | None = None

        # http is True if the event comes from HTTP API gateway
        # otherwise it is false and the event is from a REST API
        http = "version" in event

        if "authorizer" in request_ctx:
            remote_user = request_ctx["authorizer"].get("principalId")
        elif "identity" in request_ctx:
            remote_user = request_ctx["identity"].get("userArn")

        # Compute script_name and path
        path = event["rawPath" if http else "path"]
        script_name = ""
        stage = request_ctx.get("stage", "$default")
        if stage not in ["$default", "default"]:
            script_name = f"/{stage}"
            path = path.replace(script_name, "", 1)

        # HTTP method used
        http_method = (
            request_ctx["http"]["method"] if http else request_ctx["httpMethod"]
        )

        # Normalized headers
        headers = {k.title(): v for k, v in event["headers"].items()}

        # Body
        body = event.get("body", "")
        if event.get("isBase64Encoded", "false") == "true":
            body = base64.b64decode(body)
        elif body:
            body = body.encode("utf-8")
        else:
            body = b""

        query_string_param = event.get("multiValueQueryStringParameters")
        environ = {
            "PATH_INFO": path,
            "QUERY_STRING": event["rawQueryString"]
            if http
            else urlencode(query_string_param, doseq=True)
            if query_string_param
            else "",
            "REMOTE_ADDR": request_ctx["identity"]["sourceIp"],
            "REQUEST_METHOD": http_method,
            "SCRIPT_NAME": script_name,
            "HTTP_HOST": headers["Host"],
            "SERVER_NAME": headers["Host"],
            "SERVER_PORT": headers.get("X-Forwarded-Port", "80"),
            "SERVER_PROTOCOL": str("HTTP/1.1"),
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": headers.get("X-Forwarded-Proto", "http"),
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": sys.stdout,
            "wsgi.multiprocess": False,
            "wsgi.multithread": False,
            "wsgi.run_once": False,
        }

        # Set content_type and content_length if necessary
        if http_method in ["POST", "PUT", "PATCH", "DELETE"]:
            if "Content-Type" in headers:
                environ["CONTENT_TYPE"] = headers["Content-Type"]
            environ["CONTENT_LENGTH"] = str(len(body))

        # Export headers into the WSGI environment
        for header in headers:
            wsgi_name = "HTTP_" + header.upper().replace("-", "_")
            environ[wsgi_name] = headers[header]

        # Set REMOTE_USER if necessary
        if remote_user:
            environ["REMOTE_USER"] = remote_user

        # For logging purpose
        print(
            json.dumps(
                {
                    k: v
                    for k, v in environ.items()
                    if k not in ("wsgi.input", "wsgi.errors")
                }
            )
        )
        return environ
