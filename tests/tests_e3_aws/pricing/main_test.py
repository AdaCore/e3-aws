from __future__ import annotations
from typing import TYPE_CHECKING
import pytest
import boto3
import json
from botocore.stub import Stubber

from e3.aws.pricing import Pricing

if TYPE_CHECKING:
    from collections.abc import Iterable


# EC2 instance price
INSTANCE_PRICE = 0.177

# EC2 instance price information
INSTANCE_PRICE_INFORMATION = {
    "product": {
        "attributes": {
            "operatingSystem": "Ubuntu Pro",
            "regionCode": "us-east-1",
            "instanceType": "c6i.xlarge",
        },
    },
    "terms": {
        "OnDemand": {
            "YD4JEF3ADAGG84PN.JRTCKXETXF": {
                "priceDimensions": {
                    "YD4JEF3ADAGG84PN.JRTCKXETXF.6YS6EN2CT7": {
                        "unit": "Hrs",
                        "endRange": "Inf",
                        "pricePerUnit": {"USD": str(INSTANCE_PRICE)},
                    }
                },
            }
        }
    },
}

# Response returned by client.get_products
GET_PRODUCTS_RESPONSE = {"PriceList": [json.dumps(INSTANCE_PRICE_INFORMATION)]}

# Parameters for calling client.get_products
GET_PRODUCTS_PARAMS = {
    "Filters": [
        {
            "Field": "operatingSystem",
            "Type": "TERM_MATCH",
            "Value": "Ubuntu Pro",
        },
        {"Field": "instanceType", "Type": "TERM_MATCH", "Value": "c6.2xlarge"},
        {
            "Field": "location",
            "Type": "TERM_MATCH",
            "Value": "US East (N. Virginia)",
        },
    ],
    "ServiceCode": "AmazonEC2",
}

# Parameters with on-demand filters
ON_DEMAND_GET_PRODUCTS_PARAMS = {
    **GET_PRODUCTS_PARAMS,
    "Filters": [
        {"Field": "capacitystatus", "Type": "TERM_MATCH", "Value": "Used"},
        {"Field": "preInstalledSw", "Type": "TERM_MATCH", "Value": "NA"},
        {"Field": "tenancy", "Type": "TERM_MATCH", "Value": "shared"},
    ]
    + GET_PRODUCTS_PARAMS["Filters"],
}


@pytest.fixture
def client() -> Iterable[Pricing]:
    """Return a client for Pricing."""
    client = boto3.client("pricing", region_name="us-east-1")

    yield Pricing(client=client)


def test_ec2_price_information(client: Pricing) -> None:
    """Test ec2_price_information."""
    stubber = Stubber(client.client)
    stubber.add_response(
        "get_products",
        GET_PRODUCTS_RESPONSE,
        GET_PRODUCTS_PARAMS,
    )
    with stubber:
        # The first time the response should be cached so we need only one stub
        for _ in range(2):
            price_information = client.ec2_price_information(
                instance_type="c6.2xlarge", os="Ubuntu Pro", region="us-east-1"
            )

            assert price_information == [INSTANCE_PRICE_INFORMATION]


def test_ec2_on_demand_price(client: Pricing) -> None:
    """Test ec2_on_demand_price."""
    stubber = Stubber(client.client)
    stubber.add_response(
        "get_products",
        GET_PRODUCTS_RESPONSE,
        ON_DEMAND_GET_PRODUCTS_PARAMS,
    )
    with stubber:
        price = client.ec2_on_demand_price(
            instance_type="c6.2xlarge", os="Ubuntu Pro", region="us-east-1"
        )

        assert price == INSTANCE_PRICE
