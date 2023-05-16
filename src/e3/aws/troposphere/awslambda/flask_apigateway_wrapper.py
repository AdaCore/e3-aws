# The following package is packaged automatically with Flask lambda.
# Do not introduce dependencies outside Python standard library.
from __future__ import annotations
from typing import TYPE_CHECKING, cast
import json
import io
import sys
import base64
from urllib.parse import urlencode

if TYPE_CHECKING:
    from typing import Any, TypedDict
    from typing_extensions import NotRequired

    class FlaskLambdaResponse(TypedDict):
        statusCode: int
        headers: dict[str, Any]
        body: Any
        isBase64Encoded: NotRequired[bool]


# List of MIME types that should not be base64 encoded. MIME types within `text/*`
# are included by default.
TEXT_MIME_TYPES = [
    "application/json",
    "application/javascript",
    "application/xml",
    "application/vnd.api+json",
    "image/svg+xml",
]


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

    def lambda_handler(self, event: dict, context: dict) -> FlaskLambdaResponse:
        """Lambda entry point."""
        self.status = None
        self.response_headers = None

        body = next(
            self.app.wsgi_app(
                self.create_flask_wsgi_environ(event, context), self.start_response
            )
        )

        returndict: FlaskLambdaResponse = {
            "statusCode": cast(int, self.status),
            "headers": cast(dict, self.response_headers),
            "body": body,
        }

        # Extract the MIME type from Content-Type header
        mime_type = (
            cast(dict, self.response_headers)
            .get("Content-Type", "text/plain")
            .split(";")[0]
        )

        # Base64 encode non-text response
        if (
            not mime_type.startswith("text/") and mime_type not in TEXT_MIME_TYPES
        ) or cast(dict, self.response_headers).get("Content-Encoding", ""):
            returndict["body"] = base64.b64encode(body).decode("utf-8")
            returndict["isBase64Encoded"] = True

        return returndict

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

        # Set values for an HTTP event
        if http:
            # HTTP method used
            http_method = request_ctx["http"]["method"]
            path = event["rawPath"]

            # set environ items
            query_string = event["rawQueryString"]
            remote_addr = request_ctx["http"]["sourceIp"]

        # Set values for a REST API event
        else:
            # HTTP method used
            http_method = request_ctx["httpMethod"]
            path = event["path"]

            # set environ items
            query_string = (
                urlencode(q, doseq=True)
                if (q := event.get("multiValueQueryStringParameters"))
                else ""
            )
            remote_addr = request_ctx["identity"]["sourceIp"]

        # Compute script_name and path
        script_name = ""
        stage = request_ctx.get("stage", "$default")
        if stage not in ["$default", "default"]:
            script_name = f"/{stage}"
            path = path.replace(script_name, "", 1)

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

        environ = {
            "PATH_INFO": path,
            "QUERY_STRING": query_string,
            "REMOTE_ADDR": remote_addr,
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
