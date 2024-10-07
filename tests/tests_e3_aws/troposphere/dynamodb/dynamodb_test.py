from __future__ import annotations
from typing import Any, cast
import os
import json
from troposphere import Ref
from e3.aws.troposphere import Stack
from e3.aws.troposphere.dynamodb import (
    Table,
    GlobalSecondaryIndex,
    ALL_PROJECTION,
    INCLUDE_PROJECTION,
)


SOURCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "source_dir")
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


EXPECTED_TABLE_DEFAULT_TEMPLATE = {
    "Mytable": {
        "Properties": {
            "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "N"}],
            "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10,
            },
            "TableName": "mytable",
        },
        "Type": "AWS::DynamoDB::Table",
    },
}


EXPECTED_TABLE_TEMPLATE = {
    "Mytable": {
        "Properties": {
            **cast(
                dict[str, Any], EXPECTED_TABLE_DEFAULT_TEMPLATE["Mytable"]["Properties"]
            ),
            **{
                "Tags": [{"Key": "tagkey", "Value": "tagvalue"}],
                "TimeToLiveSpecification": {
                    "AttributeName": "ExpirationTime",
                    "Enabled": True,
                },
                "BillingMode": "PROVISIONED",
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": 20,
                    "WriteCapacityUnits": {"Ref": "WriteCapacityUnits"},
                },
                "StreamSpecification": {"StreamViewType": "NEW_IMAGE"},
            },
        },
        "Type": "AWS::DynamoDB::Table",
    },
}


def test_table_default(stack: Stack) -> None:
    """Test default Table creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        Table(
            name="mytable", attribute_definitions={"id": "N"}, key_schema={"id": "HASH"}
        )
    )
    assert stack.export()["Resources"] == EXPECTED_TABLE_DEFAULT_TEMPLATE


def test_table(stack: Stack) -> None:
    """Test Table creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        Table(
            name="mytable",
            attribute_definitions={"id": "N"},
            key_schema={"id": "HASH"},
            tags={"tagkey": "tagvalue"},
            point_in_time_recovery_enabled=True,
            billing_mode="PROVISIONED",
            read_capacity_units=20,
            write_capacity_units=Ref("WriteCapacityUnits"),
            time_to_live_attribute_name="ExpirationTime",
            time_to_live_enabled=True,
            stream_enabled=True,
            stream_view_type="NEW_IMAGE",
        )
    )
    assert stack.export()["Resources"] == EXPECTED_TABLE_TEMPLATE


def test_table_with_gsi(stack: Stack) -> None:
    """Create a table with Global Secondary Indexes."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        Table(
            name="mytable",
            attribute_definitions={"id": "N", "prop1": "S", "prop2": "S", "prop3": "S"},
            key_schema={"id": "HASH", "prop1": "RANGE"},
            global_secondary_indexes=[
                GlobalSecondaryIndex(
                    index_name="prop1_index",
                    key_schema={"prop1": "HASH", "id": "RANGE"},
                    projection_type=ALL_PROJECTION,
                ),
                GlobalSecondaryIndex(
                    index_name="prop2_index",
                    key_schema={"prop2": "HASH"},
                    projection_type=INCLUDE_PROJECTION,
                    non_key_attributes=["prop3"],
                ),
            ],
            point_in_time_recovery_enabled=True,
        )
    )

    with open(
        os.path.join(TEST_DIR, "dynamodb_table_with_gsi.json"),
    ) as fd:
        expected_table_template = json.load(fd)

    assert stack.export()["Resources"] == expected_table_template
