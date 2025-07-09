from __future__ import annotations
from typing import TYPE_CHECKING
import re
from datetime import datetime

from dateutil.parser import parse as parse_date
from e3.aws import session
from e3.aws.ec2 import BlockDeviceMapping, EC2Element

if TYPE_CHECKING:
    from typing import Any

    from e3.aws import Session


class AMI(EC2Element):
    """Represent an AMI."""

    PROPERTIES = {
        "ImageId": "id",
        "OwnerId": "owner_id",
        "Public": "public",
        "RootDeviceName": "root_device",
    }

    id: str
    """The ID of the AMI."""
    owner_id: str
    """The ID of the Amazon Web Services account that owns the image."""
    public: bool
    """Indicates whether the image has public launch permissions."""
    root_device: str
    """The device name of the root device volume (for example, /dev/sda1)."""

    @session()
    def __init__(
        self,
        ami_id: str,
        region: str | None = None,
        data: dict[str, Any] | None = None,
        session: Session | None = None,
    ) -> None:
        """Inialize an AMI description object.

        :param ami_id: the id of the AMI
        :param region: region in which the AMI is present. If None then
            use default region
        :param data: a dict representing the metadata of the AMI. If None then
            download AMI description using EC2 api
        """
        if data is None:
            assert ami_id is not None and session is not None
            data = session.client("ec2", region).describe_images(ImageIds=[ami_id])[
                "Images"
            ][0]
        super().__init__(data, region)

    @property
    def creation_date(self) -> datetime:
        """Creation date.

        :return: AMI creation date
        """
        return parse_date(self.data["CreationDate"]).replace(tzinfo=None)

    @property
    def age(self) -> int:
        """Return age of the AMI in days."""
        age = datetime.now() - self.creation_date
        return int(age.total_seconds() / (3600 * 24))

    @property
    def os_version(self) -> str:
        return self.tags.get("os_version", "unknown")

    @property
    def platform(self) -> str:
        return self.tags.get("platform", "unknown")

    @property
    def kind(self) -> str:
        return self.tags.get("kind", "unknown")

    @property
    def is_windows(self) -> bool:
        return "windows" in self.data.get("Platform", "unknown")

    @property
    def timestamp(self) -> int:
        return int(self.tags.get("timestamp", "0"))

    @property
    def block_device_mappings(self) -> list[BlockDeviceMapping]:
        return [
            BlockDeviceMapping(bdm, region=self.region)
            for bdm in self.data.get("BlockDeviceMappings", [])
        ]

    @property
    def snapshot_ids(self) -> list[str]:
        result: list[str] = []
        for device in self.block_device_mappings:
            if device.is_ebs:
                assert device.snapshot_id is not None
                result.append(device.snapshot_id)
        return result

    def __str__(self) -> str:
        return "%-12s %-24s: %s" % (
            self.region,
            self.data["ImageId"],
            self.data.get("Description", ""),
        )

    @classmethod
    @session()
    def ls(
        cls,
        filters: list[dict[str, Any]] | None = None,
        session: Session | None = None,
        owners: list[str] | None = None,
    ) -> list[AMI]:
        """List user AMIs.

        :param filters: same as Filters parameters of describe_images
            (see botocore)
        :return a list of images
        :param owners: a list of accounts owning the AMIs we want to list,
            by default it is set at 'self' to list all the AMIs belonging to
            the account we are in. This is the same as Owners parameter of
            describe_images (see botocore)
        """
        assert session is not None
        if filters is None:
            filters = []
        if owners is None:
            owners = ["self"]
        result = []
        for r in session.regions:
            c = session.client("ec2", r)
            region_result = c.describe_images(Owners=owners, Filters=filters)
            for ami in region_result["Images"]:
                result.append(AMI(ami["ImageId"], r, data=ami, session=session))
        return result

    @classmethod
    @session()
    def find(
        cls,
        platform: str | None = None,
        os_version: str | None = None,
        kind: str | None = None,
        region: str | None = None,
        session: Session | None = None,
        owners: list[str] | None = None,
        **kwargs: Any,
    ) -> list[AMI]:
        """Find AMIs.

        Only AMIs with platform, timestamps, os_version are considered.

        If kind is not None only consider AMIs also having a kind tag.

        :param platform: platform to match. If None all platforms are matched
        :param os_version: os_version to match. If None all os_versions are
            matched
        :param kind: kind to match. If None all regions are matched
        :param region: region to match. If None all regions are matched
        :param kwargs: additional filters on tags. parameter name if the tag
            name and the associated value the regexp
        :param owners: a list of accounts owning the AMIs we want to find,
            same as Owners parameter of describe_images (see botocore)
        :return: a list of AMI
        """
        assert session is not None
        result: dict[tuple[str, str, str], tuple[int, AMI]] = {}

        filters = [
            {"Name": "tag-key", "Values": ["platform"]},
            {"Name": "tag-key", "Values": ["timestamp"]},
            {"Name": "tag-key", "Values": ["os_version"]},
        ]
        if kind is not None:
            filters.append({"Name": "tag-key", "Values": ["kind"]})

        all_images = AMI.ls(filters=filters, session=session, owners=owners)

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
        cls,
        platform: str,
        os_version: str,
        kind: str | None = None,
        region: str | None = None,
        session: Session | None = None,
        owners: list[str] | None = None,
        **kwargs: Any,
    ) -> AMI:
        """Select one AMI based on platform, os_version and kind.

        :param platform: platform name
        :param os_version: OS version
        :param kind: kind
        :param region: region name or None (default region)
        :param owners: a list of accounts owning the AMIs we want to select,
            same as Owners parameter of describe_images (see botocore)
        :return: a list of AMI
        :return: one AMI
        """
        if region is None:
            assert session is not None
            region = session.default_region

        kind_filter = kind + "$" if kind is not None else None
        result = AMI.find(
            platform=platform + "$",
            os_version=os_version + "$",
            kind=kind_filter,
            region=region,
            session=session,
            owners=owners,
            **kwargs,
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
