from __future__ import annotations
import json
from pkg_resources import resource_filename


def get_region_name(region_code: str) -> str | None:
    """Translate region code to region name.

    This makes use of data/endpoints.json from botocore to map
    from one to the other.

    :param region_code: region code
    :return: region name or None if the region code is not found
    """
    endpoint_file = resource_filename("botocore", "data/endpoints.json")
    with open(endpoint_file) as f:
        data = json.load(f)

    return data["partitions"][0]["regions"].get(region_code, {}).get("description")
