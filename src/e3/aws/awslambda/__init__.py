"""Provide helpers for interacting with AWS Lambda functions."""

from __future__ import annotations

import json

from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    import botocore.client

    from typing import Any

LAMBDA_SUCCESS_STATUS = 200
"""Expected HTTP status code for a successful Lambda invocation."""


class LambdaInvokeResponse(TypedDict, total=False):
    """Represent the response of a Lambda function invocation.

    This is the boto3 invoke response with ``Payload`` already read and decoded.
    """

    StatusCode: int
    """HTTP status code of the invocation (200 on success)."""
    Payload: dict[str, Any] | list[Any] | bytes
    """Decoded response body: parsed JSON or raw bytes."""
    FunctionError: str
    """Set when the function crashed (e.g. ``"Handled"`` or ``"Unhandled"``)."""
    LogResult: str
    """Base64-encoded tail of the execution log (only when LogType is ``"Tail"``)."""
    ExecutedVersion: str
    """Version of the function that was executed."""
    ResponseMetadata: dict[str, Any]
    """boto3 response metadata."""


class LambdaEmptyPayloadError(Exception):
    """Raised when a Lambda function returns a JSON null payload."""


class LambdaUnexpectedStatusError(Exception):
    """Raised when a Lambda function invocation fails at the AWS level."""


class LambdaExecutionError(Exception):
    """Raised when a Lambda function is invoked successfully but its code crashes."""

    def __init__(
        self, function_name: str, error_code: str, payload: dict[str, Any]
    ) -> None:
        """Initialize a LambdaExecutionError.

        :param function_name: the name of the Lambda function that crashed
        :param error_code: the FunctionError code returned by AWS
        :param payload: the error payload returned by the Lambda function
        """
        self.function_name = function_name
        self.error_code = error_code
        self.payload = payload

        details = payload.get("errorMessage", "No details provided")
        super().__init__(f"Lambda {function_name!r} crashed ({error_code}): {details}")


def invoke(
    client: botocore.client.BaseClient,
    function_name: str,
    payload: dict[str, Any] | None = None,
) -> LambdaInvokeResponse:
    """Invoke a Lambda function and return the decoded response.

    The ``Payload`` key in the returned dict contains the decoded response:
    a parsed JSON value (dict, list, …), raw bytes if the payload is not valid
    JSON, or ``None`` when the response body is empty.

    AWS-level errors (function not found, permission denied, throttling, etc.)
    are reported by botocore as ``ClientError`` and are **not** caught; they
    propagate to the caller unchanged.

    :param client: a botocore Lambda client
    :param function_name: the name or ARN of the Lambda function to invoke
    :param payload: optional JSON-serializable payload to send to the function
    :raise botocore.exceptions.ClientError: if the AWS API call itself fails
        (e.g. function does not exist, insufficient permissions, throttling)
    :raise LambdaUnexpectedStatusError: if the AWS invoke status code is not 200
    :raise LambdaExecutionError: if the Lambda function code crashes (unhandled
        exception, timeout, syntax error, etc.)
    :raise LambdaEmptyPayloadError: if the Lambda function returns a JSON null payload
    :return: the full boto3 invoke response with ``Payload`` already read and decoded
    """
    params: dict[str, Any] = {
        "FunctionName": function_name,
        "InvocationType": "RequestResponse",
        "LogType": "None",
    }

    if payload is not None:
        params["Payload"] = json.dumps(payload)

    response = client.invoke(**params)

    raw_payload = response["Payload"].read()
    try:
        decoded = json.loads(raw_payload)
    except json.JSONDecodeError:
        response["Payload"] = raw_payload
    else:
        if decoded is None:
            raise LambdaEmptyPayloadError(
                f"Lambda {function_name!r} returned a null payload"
            )
        response["Payload"] = decoded

    if "FunctionError" in response:
        raise LambdaExecutionError(
            function_name=function_name,
            error_code=response["FunctionError"],
            payload=(
                response["Payload"]
                if isinstance(response["Payload"], dict)
                else {"raw_payload": str(raw_payload)}
            ),
        )

    if response["StatusCode"] != LAMBDA_SUCCESS_STATUS:
        msg = (
            f"Lambda {function_name!r} invocation returned unexpected status code:"
            f" {response['StatusCode']}"
        )
        raise LambdaUnexpectedStatusError(msg)

    return response
