from __future__ import annotations
from typing import TYPE_CHECKING
import pytest
from moto import mock_sts, mock_dynamodb
from botocore.exceptions import ClientError
import boto3
from e3.aws.dynamodb import DynamoDB

if TYPE_CHECKING:
    from typing import Any
    from collections.abc import Iterable

TABLE_NAME = "customer"
PRIMARY_KEYS = ["name"]
CUSTOMERS = [{"name": "John", "age": 32}, {"name": "Doe", "age": 23}]


def assert_customers(client: DynamoDB, customers: list[dict[str, Any]]) -> None:
    """Check that a list of customers exist in DB."""
    for customer in customers:
        item = client.get_item(
            item=customer,
            table_name=TABLE_NAME,
            keys=PRIMARY_KEYS,
        )
        assert item == customer


@pytest.fixture
def client() -> Iterable[DynamoDB]:
    """Return a client for the DynamoDB."""
    with mock_sts(), mock_dynamodb():
        client = boto3.resource("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "name", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "name", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 123, "WriteCapacityUnits": 123},
        )

        db = DynamoDB(client)
        db.load_data(items=CUSTOMERS, table_name=TABLE_NAME, keys=PRIMARY_KEYS)

        assert_customers(db, CUSTOMERS)
        yield db


def test_status(client: DynamoDB) -> None:
    """Test getting the status."""
    assert client.status(TABLE_NAME) == "ACTIVE"


def test_add_item(client: DynamoDB) -> None:
    """Test adding an item."""
    customers = list(CUSTOMERS)
    customers.append({"name": "Dupont", "age": "43"})

    client.add_item(item=customers[2], table_name=TABLE_NAME, keys=PRIMARY_KEYS)

    # Should be ok too
    client.add_item(
        item=customers[2], table_name=TABLE_NAME, keys=PRIMARY_KEYS, exist_ok=True
    )

    assert_customers(client, customers)


def test_add_item_exist(client: DynamoDB) -> None:
    """Test adding an item that already exist."""
    with pytest.raises(ClientError) as e:
        client.add_item(item=CUSTOMERS[0], table_name=TABLE_NAME, keys=PRIMARY_KEYS)

    assert e.value.response["Error"]["Code"] == "ConditionalCheckFailedException"


def test_get_item_missing(client: DynamoDB) -> None:
    """Test getting an item that doesn't exist."""
    assert (
        client.get_item(
            item={"name": "Dupont"}, table_name=TABLE_NAME, keys=PRIMARY_KEYS
        )
        == {}
    )


def test_update_item(client: DynamoDB) -> None:
    """Test updating an item."""
    customers = [dict(customer) for customer in CUSTOMERS]
    customers[0]["age"] = 33

    client.update_item(
        item=customers[0],
        table_name=TABLE_NAME,
        keys=PRIMARY_KEYS,
        data={"age": 33},
    )

    assert_customers(client, customers)


def test_update_item_condition(client: DynamoDB) -> None:
    """Test updating an item with a condition."""
    customers = [dict(customer) for customer in CUSTOMERS]
    customers[0]["age"] = 33

    # Update only if the name exists and age == 32
    client.update_item(
        item=customers[0],
        table_name=TABLE_NAME,
        keys=PRIMARY_KEYS,
        data={"age": 33},
        condition_expression="attribute_exists(#n) AND #a = :a",
        expression_attribute_names={"#n": "name", "#a": "age"},
        expression_attribute_values={":a": 32},
    )

    assert_customers(client, customers)


def test_query_items(client: DynamoDB) -> None:
    """Test querying items."""
    items = client.query_items(table_name=TABLE_NAME, query={"name": ["John"]})
    assert len(items) == 1
    assert items[0] == CUSTOMERS[0]


def test_scan(client: DynamoDB) -> None:
    """Test querying items."""
    items = client.scan(table_name=TABLE_NAME, query={"name": ["John"]})
    assert len(items) == 1
    assert items[0] == CUSTOMERS[0]
