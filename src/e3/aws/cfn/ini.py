class CfnConfig(object):
    """A cfn-ini config."""

    def __init__(self):
        """Initialize a config."""
        self.files = {}
        self.commands = []

    def add_file(
        self, filename, mode="644", owner="root", group="root", content=None, path=None
    ):
        """Add a file to a config.

        Either content or path should be set but not both.

        :param filename: path on the target system
        :type filename: str
        :param mode: mode for the file (three digit format like chmod)
        :type mode: str
        :param owner: owner (default: root)
        :type owner: str
        :param group: group (default: root)
        :type group: str
        :param content: file content
        :type content: str | None
        :param path: path to file containing the content
        :type path: str | None
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
        self, filename, url, authentication, mode="644", owner="root", group="root"
    ):
        """Add file to a config where file body is on S3.

        :param filename: path on the target system
        :type filename: str
        :param url: s3 url to the resource. Should be in the format:
            https://[bucket].s3.amazonaws.com/[key]
        :type url: str
        :param authentication: name of an authentication method to use
        :type authentication: str
        :param mode: mode for the file (three digit format like chmod)
        :type mode: str
        :param owner: owner (default: root)
        :type owner: str
        :param group: group (default: root)
        :type group: str
        """
        self.files[filename] = {
            "mode": "000" + mode,
            "owner": owner,
            "group": group,
            "source": url,
            "authentication": authentication,
        }

    def add_command(self, command):
        """Add a command to the config.

        Commands are run in the order in which they are added

        :param command: command to launch
        :type command: str
        """
        self.commands.append(command)

    @property
    def properties(self):
        """Serialize object.

        Used to export to cloudformation.

        :rtype: dict
        """
        result = {"files": self.files, "commands": {}}
        for index, command in enumerate(self.commands):
            # Command name define the order in which they are executed.
            # Alphanumeric order thus the need for leading zeros when
            # generating the command names based on integers.
            result["commands"]["%04d" % index] = {}
            result["commands"]["%04d" % index]["command"] = command
        return result


class CfnIni(object):
    """Represent an AWS::CloudFormation::Init resource."""

    def __init__(self):
        """Initialize cfn-ini data."""
        self.config_sets = {}
        self.configs = {}

    def add_config_set(self, name, config_list):
        """Add a config set.

        :param name: name of the config set
        :type name: str
        :param config_list: list of config names
        :type config_list: list[str]
        """
        for config in config_list:
            assert config in self.configs
        self.config_sets[name] = config_list

    def add_config(self, name, config):
        """Add a configuration.

        :param name: configuration name
        :type name: str
        :param config: config content
        :type config: CfnConfig
        """
        assert isinstance(config, CfnConfig)
        assert name != "configSets", "configSets is not a valid config name"
        self.configs[name] = config

    @property
    def properties(self):
        """Serialize object.

        Used to export to cloudformation.

        :rtype: dict
        """
        result = {}
        if self.config_sets:
            result["configSets"] = self.config_sets
        for name, config in self.configs.items():
            result[name] = config.properties
        return result
