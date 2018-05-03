import re

from e3.env import Env


class AMI(object):
    """Represent an AMI."""

    def __init__(self, ami_id, region=None, data=None):
        """Inialize an AMI description object.

        :param ami_id: the id of the AMI
        :type ami_id: str
        :param region: region in which the AMI is present. If None then
            use default region
        :type region: None | str
        :param data: a dict representing the metadata of the AMI. If None then
            download AMI description using EC2 api
        :type data: dict | None
        """
        self.ami_id = ami_id
        self.region = region
        if self.region is None:
            self.region = Env().aws_env.default_region

        if data is None:
            aws_env = Env().aws_env
            self.data = aws_env.client('ec2', self.region).describe_images(
                ImageIds=[self.ami_id])['Images'][0]
        else:
            self.data = data

        # compute tags
        self.tags = {el['Key']: el['Value'] for el in self.data['Tags']}

    @property
    def id(self):
        return self.data['ImageId']

    @property
    def root_device(self):
        return self.data['RootDeviceName']

    @property
    def os_version(self):
        return self.tags.get('os_version', 'unknown')

    @property
    def platform(self):
        return self.tags.get('platform', 'unknown')

    @property
    def is_windows(self):
        return 'windows' in self.data.get('Platform', 'unknown')

    @property
    def timestamp(self):
        return int(self.tags.get('timestamp', '0'))

    def __str__(self):
        return '%-12s %-24s: %s' % (self.region,
                                    self.data['ImageId'],
                                    self.data.get('Description', ''))

    @classmethod
    def ls(cls, filters=None):
        """List user AMIs.

        :param filters: same as Filters parameters of describe_images
            (see botocore)
        :type filters: dict
        :return a list of images
        :rtype: list[AMI]
        """
        aws_env = Env().aws_env
        if filters is None:
            filters = []
        result = []
        for r in aws_env.regions:
            c = aws_env.client('ec2', r)
            region_result = c.describe_images(Owners=['self'], Filters=filters)
            for ami in region_result['Images']:
                result.append(AMI(ami['ImageId'], r, data=ami))
        return result

    @classmethod
    def find(cls, platform=None, os_version=None, region=None):
        """Find AMIs.

        Only AMIs with platform, timestamps and os_version tags are considered.

        :param platform: platform to match. If None all platforms are matched
        :type platform: str | None
        :param os_version: os_version to match. If None all os_versions are
            matched
        :type os_version: str | None
        :param region: region to match. If None all regions are matched
        :type region: str | None
        """
        result = {}
        all_images = AMI.ls(
            filters=[{'Name': 'tag-key', 'Values': ['platform']},
                     {'Name': 'tag-key', 'Values': ['timestamp']},
                     {'Name': 'tag-key', 'Values': ['os_version']}])

        for ami in all_images:
            key = (ami.region, ami.platform, ami.os_version)
            if ((platform is not None and
                 not re.match(platform, ami.platform)) or
                    (os_version is not None and
                     not re.match(os_version, ami.os_version)) or
                    (region is not None and not re.match(region, ami.region))):
                continue

            if key not in result or result[key][0] < ami.timestamp:
                result[key] = (ami.timestamp, ami)

        return [el[1] for el in result.values()]

    @classmethod
    def select(cls, platform, os_version, region=None):
        """Select one AMI based on platform and os_version.

        :param platform: platform name
        :type platform: str
        :param os_version: OS version
        :type os_version: str
        :param region: region name or None (default region)
        :type region: str | None
        :return: one AMI
        :rtype: AMI
        """
        if region is None:
            region = Env().aws_env.default_region
        result = AMI.find(platform=platform + '$',
                          os_version=os_version + '$',
                          region=region)
        assert len(result) == 1, \
            'cannot find AMI %s (%s) in region %s' % (platform,
                                                      os_version,
                                                      region)
        return result[0]
