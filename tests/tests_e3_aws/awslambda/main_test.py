"""Provide unit tests for the awslambda module."""

from __future__ import annotations

import io
import json

import boto3
import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber

from e3.aws.awslambda import (
    LAMBDA_SUCCESS_STATUS,
    LambdaEmptyPayloadError,
    LambdaExecutionError,
    LambdaInvalidPayloadError,
    LambdaUnexpectedStatusError,
    invoke,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import botocore.client

LAMBDA_UNEXPECTED_STATUS_CODE = 401
REGION = "us-east-1"
FUNCTION_NAME = "test-function"
BASE_INVOKE_PARAMS = {
    "FunctionName": FUNCTION_NAME,
    "InvocationType": "RequestResponse",
    "LogType": "None",
}


def _make_payload(data: bytes) -> StreamingBody:
    """Return a StreamingBody wrapping data."""
    return StreamingBody(io.BytesIO(data), len(data))


@pytest.fixture
def client() -> botocore.client.BaseClient:
    """Return a boto3 Lambda client."""
    return boto3.client("lambda", region_name=REGION)


def test_invoke_without_payload(client: botocore.client.BaseClient) -> None:
    """Test invoke without a payload does not include Payload in the API call.

    Also verifies that the response Payload is decoded as parsed JSON.
    """
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {
                "StatusCode": LAMBDA_SUCCESS_STATUS,
                "Payload": _make_payload(b'{"result": "ok"}'),
            },
            BASE_INVOKE_PARAMS,
        )
        result = invoke(client, FUNCTION_NAME)

    assert result["StatusCode"] == LAMBDA_SUCCESS_STATUS
    assert result["Payload"] == {"result": "ok"}


def test_invoke_with_payload(client: botocore.client.BaseClient) -> None:
    """Test invoke serializes the payload and passes it to the API call."""
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {
                "StatusCode": LAMBDA_SUCCESS_STATUS,
                "Payload": _make_payload(b'{"key": "value"}'),
            },
            {**BASE_INVOKE_PARAMS, "Payload": json.dumps({"key": "value"})},
        )
        result = invoke(client, FUNCTION_NAME, payload={"key": "value"})

    assert result["StatusCode"] == LAMBDA_SUCCESS_STATUS
    assert result["Payload"] == {"key": "value"}


def test_invoke_raises_invalid_payload_error_when_payload_is_not_json(
    client: botocore.client.BaseClient,
) -> None:
    """Test LambdaInvalidPayloadError is raised when payload is not valid JSON."""
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {
                "StatusCode": LAMBDA_SUCCESS_STATUS,
                "Payload": _make_payload(b"not-json"),
            },
            BASE_INVOKE_PARAMS,
        )
        with pytest.raises(LambdaInvalidPayloadError) as exc_info:
            invoke(client, FUNCTION_NAME)

    assert FUNCTION_NAME in str(exc_info.value)


def test_invoke_raises_invalid_payload_error_when_response_is_empty(
    client: botocore.client.BaseClient,
) -> None:
    """Test invoke raises LambdaInvalidPayloadError when the response body is empty."""
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {"StatusCode": LAMBDA_SUCCESS_STATUS, "Payload": _make_payload(b"")},
            BASE_INVOKE_PARAMS,
        )
        with pytest.raises(LambdaInvalidPayloadError) as exc_info:
            invoke(client, FUNCTION_NAME)

    assert FUNCTION_NAME in str(exc_info.value)


def test_invoke_raises_empty_payload_error_when_payload_is_json_null(
    client: botocore.client.BaseClient,
) -> None:
    """Test invoke raises LambdaEmptyPayloadError when the response is JSON null."""
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {"StatusCode": LAMBDA_SUCCESS_STATUS, "Payload": _make_payload(b"null")},
            BASE_INVOKE_PARAMS,
        )
        with pytest.raises(LambdaEmptyPayloadError) as exc_info:
            invoke(client, FUNCTION_NAME)

    assert FUNCTION_NAME in str(exc_info.value)


def test_invoke_raises_execution_error_on_function_error(
    client: botocore.client.BaseClient,
) -> None:
    """Test invoke raises LambdaExecutionError when FunctionError is in the response."""
    error_payload = json.dumps(
        {"errorMessage": "something went wrong", "errorType": "RuntimeError"}
    ).encode()
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {
                "StatusCode": LAMBDA_SUCCESS_STATUS,
                "FunctionError": "Unhandled",
                "Payload": _make_payload(error_payload),
            },
            BASE_INVOKE_PARAMS,
        )
        with pytest.raises(LambdaExecutionError) as exc_info:
            invoke(client, FUNCTION_NAME)

    error = exc_info.value
    assert error.function_name == FUNCTION_NAME
    assert error.error_code == "Unhandled"
    assert error.payload == {
        "errorMessage": "something went wrong",
        "errorType": "RuntimeError",
    }
    assert "something went wrong" in str(error)


def test_invoke_raises_execution_error_without_error_message(
    client: botocore.client.BaseClient,
) -> None:
    """Test LambdaExecutionError message when errorMessage is absent from payload."""
    error_payload = json.dumps({"errorType": "SomeError"}).encode()
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {
                "StatusCode": LAMBDA_SUCCESS_STATUS,
                "FunctionError": "Handled",
                "Payload": _make_payload(error_payload),
            },
            BASE_INVOKE_PARAMS,
        )
        with pytest.raises(LambdaExecutionError) as exc_info:
            invoke(client, FUNCTION_NAME)

    assert "No details provided" in str(exc_info.value)


def test_invoke_raises_invalid_payload_error_when_function_error_payload_is_not_json(
    client: botocore.client.BaseClient,
) -> None:
    """Test LambdaInvalidPayloadError raised for non-JSON FunctionError payload."""
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {
                "StatusCode": LAMBDA_SUCCESS_STATUS,
                "FunctionError": "Unhandled",
                "Payload": _make_payload(b"not-valid-json"),
            },
            BASE_INVOKE_PARAMS,
        )
        with pytest.raises(LambdaInvalidPayloadError) as exc_info:
            invoke(client, FUNCTION_NAME)

    assert FUNCTION_NAME in str(exc_info.value)


def test_invoke_raises_unexpected_status_error(
    client: botocore.client.BaseClient,
) -> None:
    """Test invoke raises LambdaUnexpectedStatusError for non-200 status codes."""
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke",
            {
                "StatusCode": LAMBDA_UNEXPECTED_STATUS_CODE,
                "Payload": _make_payload(b"{}"),
            },
            BASE_INVOKE_PARAMS,
        )
        with pytest.raises(LambdaUnexpectedStatusError) as exc_info:
            invoke(client, FUNCTION_NAME)

    assert FUNCTION_NAME in str(exc_info.value)
    assert str(LAMBDA_UNEXPECTED_STATUS_CODE) in str(exc_info.value)
