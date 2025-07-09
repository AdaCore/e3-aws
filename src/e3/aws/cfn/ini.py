from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class CfnConfig(object):
    """A cfn-ini config."""

    def __init__(self) -> None:
        """Initialize a config."""
        self.files: dict[str, dict[str, str]] = {}
        self.commands: list[str] = []

    def add_file(
        self,
        filename: str,
        mode: str = "644",
        owner: str = "root",
        group: str = "root",
        content: str | None = None,
        path: str | None = None,
    ) -> None:
        """Add a file to a config.

        Either content or path should be set but not both.

        :param filename: path on the target system
        :param mode: mode for the file (three digit format like chmod)
        :param owner: owner (default: root)
        :param group: group (default: root)
        :param content: file content
        :param path: path to file containing the content
        """
        assert content is None or path is None, "cannot set both path and content"
        if path is not None:
            with open(path, "r") as fd:
                content = fd.read()
        assert content is not None, "no content for file"

        self.files[filename] = {
            "mode": "000" + mode,
            "owner": owner,
            "group": group,
            "content": content,
        }

    def add_s3_file(
        self,
        filename: str,
        url: str,
        authentication: str,
        mode: str = "644",
        owner: str = "root",
        group: str = "root",
    ) -> None:
        """Add file to a config where file body is on S3.

        :param filename: path on the target system
        :param url: s3 url to the resource. Should be in the format:
            https://[bucket].s3.amazonaws.com/[key]
        :param authentication: name of an authentication method to use
        :param mode: mode for the file (three digit format like chmod)
        :param owner: owner (default: root)
        :param group: group (default: root)
        """
        self.files[filename] = {
            "mode": "000" + mode,
            "owner": owner,
            "group": group,
            "source": url,
            "authentication": authentication,
        }

    def add_command(self, command: str) -> None:
        """Add a command to the config.

        Commands are run in the order in which they are added

        :param command: command to launch
        """
        self.commands.append(command)

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize object.

        Used to export to cloudformation.
        """
        # Command name define the order in which they are executed.
        # Alphanumeric order thus the need for leading zeros when
        # generating the command names based on integers.
        return {
            "files": self.files,
            "commands": {
                ("%04d" % index): {"command": command}
                for index, command in enumerate(self.commands)
            },
        }


class CfnIni(object):
    """Represent an AWS::CloudFormation::Init resource."""

    def __init__(self) -> None:
        """Initialize cfn-ini data."""
        self.config_sets: dict[str, list[str]] = {}
        self.configs: dict[str, CfnConfig] = {}

    def add_config_set(self, name: str, config_list: list[str]) -> None:
        """Add a config set.

        :param name: name of the config set
        :param config_list: list of config names
        """
        for config in config_list:
            assert config in self.configs
        self.config_sets[name] = config_list

    def add_config(self, name: str, config: CfnConfig) -> None:
        """Add a configuration.

        :param name: configuration name
        :param config: config content
        """
        assert name != "configSets", "configSets is not a valid config name"
        self.configs[name] = config

    @property
    def properties(self) -> dict[str, Any]:
        """Serialize object.

        Used to export to cloudformation.
        """
        result = {}
        if self.config_sets:
            result["configSets"] = self.config_sets
        for name, config in self.configs.items():
            result[name] = config.properties
        return result
