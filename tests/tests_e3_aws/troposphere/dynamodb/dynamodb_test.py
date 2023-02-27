from __future__ import annotations
import os

from troposphere import Ref
from e3.aws.troposphere import Stack
from e3.aws.troposphere.dynamodb import Table


SOURCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "source_dir")


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
            **EXPECTED_TABLE_DEFAULT_TEMPLATE["Mytable"]["Properties"],
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
