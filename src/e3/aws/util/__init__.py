from __future__ import annotations
import json
import importlib.resources
from colorama import Fore, Style


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


def modified_diff_lines(lines: list[str]) -> list[str]:
    """Keep only the modified lines in a diff."""
    return [line for line in lines if line.startswith(("+", "-", "@"))]


def color_diff(lines: list[str]) -> list[str]:
    """Return a diff with colors.

    :param lines: the lines of the diff
    :return: the lines with colors
    """

    def color(line: str) -> str:
        """Get the color for a line.

        :param line: a line of the diff
        :return: the color for that line
        """
        if line.startswith("-"):
            return Fore.RED
        elif line.startswith("+"):
            return Fore.GREEN
        elif line.startswith("@"):
            return Fore.CYAN
        else:
            return ""

    return [f"{color(line)}{line}{Style.RESET_ALL}" for line in lines]
