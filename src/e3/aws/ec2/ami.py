import re
from datetime import datetime

from dateutil.parser import parse as parse_date
from e3.aws import session
from e3.aws.ec2 import BlockDeviceMapping, EC2Element


class AMI(EC2Element):
    """Represent an AMI."""

    PROPERTIES = {
        "ImageId": "id",
        "OwnerId": "owner_id",
        "Public": "public",
        "RootDeviceName": "root_device",
    }

    @session()
    def __init__(self, ami_id, region=None, data=None, session=None):
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
        if data is None:
            assert ami_id is not None
            data = session.client("ec2", region).describe_images(ImageIds=[ami_id])[
                "Images"
            ][0]
        super().__init__(data, region)

    @property
    def creation_date(self):
        """Creation date.

        :return: AMI creation date
        :rtype: datetime.datetime
        """
        return parse_date(self.data["CreationDate"]).replace(tzinfo=None)

    @property
    def age(self):
        """Return age of the AMI in days."""
        age = datetime.now() - self.creation_date
        return int(age.total_seconds() / (3600 * 24))

    @property
    def os_version(self):
        return self.tags.get("os_version", "unknown")

    @property
    def platform(self):
        return self.tags.get("platform", "unknown")

    @property
    def kind(self):
        return self.tags.get("kind", "unknown")

    @property
    def is_windows(self):
        return "windows" in self.data.get("Platform", "unknown")

    @property
    def timestamp(self):
        return int(self.tags.get("timestamp", "0"))

    @property
    def block_device_mappings(self):
        return [
            BlockDeviceMapping(bdm, region=self.region)
            for bdm in self.data.get("BlockDeviceMappings", [])
        ]

    @property
    def snapshot_ids(self):
        result = []
        for device in self.block_device_mappings:
            if device.is_ebs:
                result.append(device.snapshot_id)
        return result

    def __str__(self):
        return "%-12s %-24s: %s" % (
            self.region,
            self.data["ImageId"],
            self.data.get("Description", ""),
        )

    @classmethod
    @session()
    def ls(cls, filters=None, session=None):
        """List user AMIs.

        :param filters: same as Filters parameters of describe_images
            (see botocore)
        :type filters: dict
        :return a list of images
        :rtype: list[AMI]
        """
        if filters is None:
            filters = []
        result = []
        for r in session.regions:
            c = session.client("ec2", r)
            region_result = c.describe_images(Owners=["self"], Filters=filters)
            for ami in region_result["Images"]:
                result.append(AMI(ami["ImageId"], r, data=ami, session=session))
        return result

    @classmethod
    @session()
    def find(
        cls,
        platform=None,
        os_version=None,
        kind=None,
        region=None,
        session=None,
        **kwargs
    ):
        """Find AMIs.

        Only AMIs with platform, timestamps, os_version are considered.

        If kind is not None only consider AMIs also having a kind tag.

        :param platform: platform to match. If None all platforms are matched
        :type platform: str | None
        :param os_version: os_version to match. If None all os_versions are
            matched
        :type os_version: str | None
        :param kind: kind to match. If None all regions are matched
        :type kind: str | None
        :param region: region to match. If None all regions are matched
        :type region: str | None
        :param kwargs: additional filters on tags. parameter name if the tag
            name and the associated value the regexp
        :type kwargs: dict
        :return: a list of AMI
        :rtype: list[AMI]
        """
        result = {}

        filters = [
            {"Name": "tag-key", "Values": ["platform"]},
            {"Name": "tag-key", "Values": ["timestamp"]},
            {"Name": "tag-key", "Values": ["os_version"]},
        ]
        if kind is not None:
            filters.append({"Name": "tag-key", "Values": ["kind"]})

        all_images = AMI.ls(filters=filters, session=session)

        tag_filters = dict(kwargs)
        if platform is not None:
            tag_filters["platform"] = platform
        if os_version is not None:
            tag_filters["os_version"] = os_version
        if kind is not None:
            tag_filters["kind"] = kind

        for ami in all_images:
            key_l = [ami.region, ami.platform, ami.os_version]
            if kind is not None:
                key_l.append(ami.kind)
            key = tuple(key_l)

            if region is not None and not re.match(region, ami.region):
                continue

            consider_ami = True
            for tag in tag_filters:
                if not re.match(tag_filters[tag], ami.tags.get(tag, "")):
                    consider_ami = False
                    continue

            if not consider_ami:
                continue

            if key not in result or result[key][0] < ami.timestamp:
                result[key] = (ami.timestamp, ami)

        return [el[1] for el in result.values()]

    @classmethod
    @session()
    def select(
        cls, platform, os_version, kind=None, region=None, session=None, **kwargs
    ):
        """Select one AMI based on platform, os_version and kind.

        :param platform: platform name
        :type platform: str
        :param os_version: OS version
        :type os_version: str
        :param kind: kind
        :type kind: str
        :param region: region name or None (default region)
        :type region: str | None
        :return: one AMI
        :rtype: AMI
        """
        if region is None:
            region = session.default_region

        kind_filter = kind + "$" if kind is not None else None
        result = AMI.find(
            platform=platform + "$",
            os_version=os_version + "$",
            kind=kind_filter,
            region=region,
            session=session,
            **kwargs
        )
        assert (
            len(result) == 1
        ), "cannot find AMI %s (%s) of kind (%s) in region %s %s" % (
            platform,
            os_version,
            kind,
            region,
            kwargs,
        )
        return result[0]
