#!/usr/bin/env python
"""Build the wheel.

dev1 in the version of the package is automatically replaced by the number
of commits since the last tagged version.

A tag v<major>.<minor>.0 is automatically added to the commit if the major
or minor version changes.
"""
from __future__ import annotations
import sys
from pathlib import Path
import re
import tomllib

from e3.main import Main
from e3.os.process import Run
from e3.log import getLogger

logger = getLogger("build_wheel")

ROOT_DIR = Path(__file__).parent


def run(cmd: list[str], fail_ok: bool | None = None) -> Run:
    """Print a command, run it, and print the result.

    :param cmd: the command
    :param fail_ok: allow the command to fail
    :return: the Run instance
    """
    logger.info(f"$ {' '.join(cmd)}")
    p = Run(cmd, cwd=ROOT_DIR)
    if p.status != 0 and not fail_ok:
        logger.error(p.out)
        sys.exit(1)

    logger.info(p.out)
    return p


def main() -> None:
    """Entrypoint."""
    main = Main()

    parser = main.argument_parser
    parser.description = "Build the wheel"
    parser.add_argument(
        "--update",
        action="store_true",
        help="Tag the commit in case of version change",
    )
    parser.add_argument(
        "--last-tag",
        help="Provide the last tagged version",
    )

    main.parse_args()
    assert main.args

    # Find and read version file
    with open(ROOT_DIR / "pyproject.toml", "rb") as f:
        version_config = tomllib.load(f)["tool"]["setuptools"]["dynamic"]["version"]

    version_path = ROOT_DIR / (
        version_config["file"]
        if "file" in version_config
        else f'src/{version_config["attr"].replace(".", "/")}.py'
    )
    with open(version_path) as f:
        version_content = f.read()

    # Extract the <major>.<minor> part.
    # We will replace the dev1 part by the number of commits since the most
    # recent tagged version
    match = re.match(r"(?P<version>\d+\.\d+)\.dev1", version_content)
    if not match:
        logger.error(f"No <major>.<minor>.dev1 version found in {version_path.name}")
        sys.exit(1)

    logger.info("Version is {}.dev1".format(version := match.group("version")))

    # Find previous version from the most recent tag
    tagged_version = main.args.last_tag
    if not tagged_version:
        # Need to unshallow the clone so we get the list of tags.
        # That command can fail for an already complete clone
        run(["git", "fetch", "--unshallow", "--tags"], fail_ok=True)
        # Describe the most recent tag
        p = run(["git", "describe", "--tags"])
        tagged_version = p.out

    # Format is v<major>.<minor>.<patch>(-<commits>)? with commits omitted if
    # the current commit is also the one tagged
    match = re.match(
        r"v(?P<version>\d+\.\d+)\.\d+(\-(?P<commits>\d+))?", tagged_version
    )
    if not match:
        logger.error(
            "Expected v<major>.<minor>.<path>(-<commits>)? "
            f"format for tag {tagged_version}"
        )
        sys.exit(1)

    # tagged_version_commits is None only if the current commit is also the one tagged
    # so there is 0 commits since that tag
    tagged_version_commits = match.group("commits")
    version_patch = tagged_version_commits if tagged_version_commits is not None else 0
    logger.info(
        "Tagged version {} commit(s) ago is {}".format(
            version_patch, tagged_version := match.group("version")
        )
    )

    # Tag the commit with <major>.<minor>.0 in case of version change.
    # Don't tag if there's already a tag (tagged_version_commits is None)
    if (
        main.args.update
        and tagged_version_commits is not None
        and version != tagged_version
    ):
        run(["git", "tag", f"v{version}.0"])

    # Replace dev1 in the version file.
    logger.info(f"Set version to {version}.{version_patch}")
    with open(version_path, "w") as f:
        f.write(version_content.replace("dev1", str(version_patch)))

    try:
        # Build the wheel
        run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "-q",
                "--no-deps",
                "-C--python-tag=py3",
                "-w",
                "build",
            ]
        )
    finally:
        # Revert change to version file
        run(["git", "restore", str(version_path)], fail_ok=True)


if __name__ == "__main__":
    main()
