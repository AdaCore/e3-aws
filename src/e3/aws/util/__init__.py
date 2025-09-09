from __future__ import annotations
import json
import importlib.resources


def get_region_name(region_code: str) -> str | None:
    """Translate region code to region name.

    This makes use of data/endpoints.json from botocore to map
    from one to the other.

    :param region_code: region code
    :return: region name or None if the region code is not found
    """
    with importlib.resources.files("botocore.data").joinpath(
        "endpoints.json"
    ).open() as f:
        data = json.load(f)

    return data["partitions"][0]["regions"].get(region_code, {}).get("description")
