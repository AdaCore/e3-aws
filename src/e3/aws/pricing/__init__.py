from __future__ import annotations
from typing import TYPE_CHECKING
import json

from e3.aws.util import get_region_name

if TYPE_CHECKING:
    from typing import Any
    import botocore

    _CacheKey = tuple[str | None, str | None, str | None]

    # This is only to avoid repeating the type everywhere
    PriceInformation = dict[str, Any]


class Pricing:
    """Pricing abstraction."""

    def __init__(self, client: botocore.client.BaseClient) -> None:
        """Initialize Pricing.

        :param client: a client for the Pricing API
        """
        self.client = client
        # Cache results of client.get_products requests
        self._cache: dict[_CacheKey, list[PriceInformation]] = {}

    def _cache_key(
        self,
        instance_type: str | None = None,
        os: str | None = None,
        region: str | None = None,
    ) -> _CacheKey:
        """Get the key for cache.

        :param instance_type: EC2 instance type
        :param os: operating system
        :param region: region code
        :return: key for cache
        """
        return (instance_type, os, region)

    def ec2_price_information(
        self,
        instance_type: str | None = None,
        os: str | None = None,
        region: str | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[PriceInformation]:
        """Get pricing informations for EC2 instances.

        :param instance_type: filter by EC2 instance type
        :param os: filter by operating system
        :param region: filter by region code
        :param filters: additional filters for client.get_products
        :return: pricing information as returned by client.get_products
        """
        # Check if the price information is already cached
        key = self._cache_key(instance_type=instance_type, os=os, region=region)
        if key in self._cache:
            return self._cache[key]

        # Even though the API data contains regionCode field, it will not return
        # accurate data. However using the location field will, but then we need to
        # translate the region code into a region name. You could skip this by using
        # the region names in your code directly, but most other APIs are using the
        # region code.
        filters = filters if filters is not None else []
        for field, value in (
            ("operatingSystem", os),
            ("instanceType", instance_type),
            ("location", None if region is None else get_region_name(region)),
        ):
            if value is not None:
                filters.append(
                    {
                        "Field": field,
                        "Value": str(value),
                        "Type": "TERM_MATCH",
                    }
                )

        result: list[PriceInformation] = []
        paginator = self.client.get_paginator("get_products")
        for data in paginator.paginate(ServiceCode="AmazonEC2", Filters=filters):
            for price in data["PriceList"]:
                price = json.loads(price)

                # Cache the individual response
                attributes = price["product"]["attributes"]
                self._cache[
                    self._cache_key(
                        instance_type=attributes["instanceType"],
                        os=attributes["operatingSystem"],
                        region=attributes["regionCode"],
                    )
                ] = [price]

                result.append(price)

        # Cache the whole response
        self._cache[key] = result
        return result

    def ec2_on_demand_price(
        self, instance_type: str, os: str, region: str
    ) -> float | None:
        """Get the on-demand hourly price of an EC2 instance.

        :param instance_type: EC2 instance type
        :param os: operating system
        :param region: region code
        :return: hourly price or None if no price information is found
        """
        prices = self.ec2_price_information(
            instance_type,
            os,
            region,
            # Filters for on-demand information only
            filters=[
                {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "shared"},
            ],
        )

        if not prices:
            return None

        price_data = list(prices[0]["terms"]["OnDemand"].values())[0]
        price_per_unit_data = list(price_data["priceDimensions"].values())[0]
        return float(price_per_unit_data["pricePerUnit"]["USD"])
