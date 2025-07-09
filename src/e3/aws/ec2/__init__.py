from __future__ import annotations
from typing import TYPE_CHECKING
from e3.aws import session
from dateutil.parser import parse as parse_date

if TYPE_CHECKING:
    from typing import Any
    from datetime import datetime

    from e3.aws import Session


class EC2Element:
    """EC2 Element.

    All objects returned by EC2 API
    """

    PROPERTIES: dict[str, Any] = {}

    def __init__(self, data: dict[str, Any], region: str | None = None) -> None:
        """Initialize an EC2 Element.

        :param data: data as returned by botocore
        :param region: region of the EC2 object
        """
        self.data = data
        self.region = region

        # Compute tags
        if "Tags" in self.data:
            self.tags = {el["Key"]: el["Value"] for el in self.data["Tags"]}
        else:
            self.tags = {}

        # Map botocore attributes declared in PROPERTIES into Python
        # properties.
        for key, name in self.PROPERTIES.items():
            setattr(
                self.__class__,
                name,
                property(lambda s, default_key=key: s.data.get(default_key)),  # type: ignore
            )

    @property
    def logical_id(self) -> str | None:
        """Cloud Formation logical id.

        :return: the id or None (if the element is not part of a stack)
        """
        return self.tags.get("aws:cloudformation:logical-id")


class SecurityGroup(EC2Element):
    """Security Group description."""

    PROPERTIES = {"GroupName": "group_name", "GroupId": "group_id"}

    group_name: str
    """The name of the security group."""
    group_id: str
    """The ID of the security group."""

    @session()
    def __init__(
        self,
        group_id: str | None = None,
        region: str | None = None,
        data: dict[str, Any] | None = None,
        session: Session | None = None,
    ) -> None:
        """Initialize a security group.

        :param group_id: group id. Used to retrieve group data
            if data parameter is None
        :param region: region of the security group
        :param data: botocore data describing the group. If None
            then data is fetched automatically using group id and
            region
        """
        if data is None:
            assert region is not None and group_id is not None and session is not None
            data = session.client("ec2", region).describe_security_groups(
                GroupIds=[group_id]
            )["SecurityGroups"][0]
        super().__init__(data, region)

    @classmethod
    @session()
    def ls(
        cls,
        filters: list[dict[str, Any]] | None = None,
        session: Session | None = None,
    ) -> list[SecurityGroup]:
        """List user security groups.

        Note that this API is cross region. All regions used when creating
        the session are used.

        :param filters: same as Filters parameters of describe_security_groups
            (see botocore)
        :return a list of images
        """
        assert session is not None
        if filters is None:
            filters = []
        result = []
        for r in session.regions:
            c = session.client("ec2", r)
            region_result = c.describe_security_groups(Filters=filters)
            for sg in region_result["SecurityGroups"]:
                result.append(SecurityGroup(sg["GroupId"], r, data=sg))
        return result


class Instance(EC2Element):
    """EC2 Instance."""

    PROPERTIES = {"InstanceId": "instance_id"}

    instance_id: str
    """The ID of the instance."""

    @session()
    def __init__(
        self,
        instance_id: str | None = None,
        region: str | None = None,
        data: dict[str, Any] | None = None,
        session: Session | None = None,
    ) -> None:
        """Initialize an EC2 instance description.

        :param instance_id: instance id. Used to retrieve instance data
            if data parameter is None
        :param region: region of the security group
        :param data: botocore data describing the instance. If None
            then data is fetched automatically using instance id and
            region
        """
        if data is None:
            assert (
                instance_id is not None and region is not None and session is not None
            )
            data = session.client("ec2", region).describe_instances(
                InstanceIds=[instance_id]
            )["Reservations"]["Instances"][0]

        super().__init__(data, region)

    @property
    def security_groups(self) -> list[SecurityGroup]:
        """List security groups attached to the instance.

        :return: a list of security groups
        """
        return [
            SecurityGroup(el["GroupId"], region=self.region)
            for el in self.data["SecurityGroups"]
        ]

    @property
    def network_interfaces(self) -> list[NetworkInterface]:
        """List network interfaces attached to an instance.

        :return: a list of network interface
        """
        return [
            NetworkInterface(ni, region=self.region)
            for ni in self.data.get("NetworkInterfaces", [])
        ]

    @property
    def has_public_ip(self) -> bool:
        """Check if instance has a public IP.

        :return: True if at least one interface has a public IP
        """
        for ni in self.network_interfaces:
            if ni.public_ip is not None:
                return True
        return False

    @property
    def block_device_mappings(self) -> list[BlockDeviceMapping]:
        """List block device mappings.

        :return: the list of mappings
        """
        return [
            BlockDeviceMapping(bdm, region=self.region)
            for bdm in self.data["BlockDeviceMappings"]
        ]

    @classmethod
    @session()
    def ls(
        cls,
        filters: list[dict[str, Any]] | None = None,
        session: Session | None = None,
    ) -> list[Instance]:
        """List user instances.

        Note that instances in "terminated" mode are ignored.

        :param filters: same as Filters parameters of describe_instances
            (see botocore)
        :return a list of instances
        """
        assert session is not None
        if filters is None:
            filters = []
        result = []
        for r in session.regions:
            c = session.client("ec2", r)
            region_result = c.describe_instances(Filters=filters)
            for reservation in region_result["Reservations"]:
                if "Instances" not in reservation:
                    continue
                for instance_data in reservation["Instances"]:
                    if instance_data["State"]["Name"] == "terminated":
                        # Ignore instance that are going to disappear soon
                        continue
                    result.append(
                        Instance(
                            instance_data["InstanceId"],
                            r,
                            data=instance_data,
                            session=session,
                        )
                    )
        return result


class BlockDeviceMapping(EC2Element):
    """Block Device Mappping."""

    PROPERTIES = {"DeviceName": "device_name"}

    device_name: str
    """The device name."""

    @property
    def is_ebs(self) -> bool:
        """Check if mapping is an EBS.

        :return: True if this is an EBS, False otherwise
        """
        return "Ebs" in self.data

    @property
    def encrypted(self) -> bool:
        """Check if the block device is encrypted.

        :return: True if encrypted, false otherwise
        """
        return "Ebs" in self.data and self.data["Ebs"].get("Encrypted", False)

    @property
    def snapshot_id(self) -> str | None:
        """Retrieve snapshot id.

        :return: the associated snaptshot if it exist
        """
        if self.is_ebs:
            return self.data["Ebs"].get("SnapshotId")
        else:
            return None


class VolumeAttachment(EC2Element):
    """Volume Attachment."""

    PROPERTIES = {
        "InstanceId": "instance_id",
        "Device": "device",
        "State": "state",
        "VolumeId": "volume_id",
        "DeleteOnTermination": "delete_on_termination",
    }

    instance_id: str
    """The ID of the instance."""
    device: str
    """The device name."""
    state: str
    """The attachment state of the volume."""
    volume_id: str
    """The ID of the volume."""
    delete_on_termination: bool
    """Indicates whether the EBS volume is deleted on instance termination."""

    def __init__(self, data: dict[str, Any], region: str | None = None) -> None:
        """Initialize Volume Attachment description."""
        super().__init__(data, region)
        self._instance_cache: Instance | None = None
        self._volume_cache: Volume | None = None

    @property
    def attach_time(self) -> datetime:
        """Return time at which attachment was done.

        :return: attach time
        """
        return parse_date(self.data["AttachTime"])

    @property
    def instance(self) -> Instance:
        """Retrieve instance attached to the volume.

        :return: an Instance object
        """
        if self._instance_cache is None:
            self._instance_cache = Instance(self.instance_id, region=self.region)
        return self._instance_cache

    @property
    def volume(self) -> Volume:
        """Retrieve the Volume.

        :return: the Volume part of the attachment.
        """
        if self._volume_cache is None:
            self._volume_cache = Volume(self.volume_id, region=self.region)
        return self._volume_cache


class Volume(EC2Element):
    """EC2 Volume."""

    PROPERTIES = {
        "VolumeId": "volume_id",
        "AvailabilityZone": "availability_zone",
        "Size": "size",
        "SnapshotId": "snapshot_id",
        "State": "state",
        "VolumeType": "volume_type",
        "Encrypted": "encrypted",
    }

    volume_id: str
    """The ID of the volume."""
    availability_zone: str
    """The Availability Zone for the volume."""
    size: int
    """The size of the volume, in GiBs."""
    snapshot_id: str
    """The snapshot from which the volume was created, if applicable."""
    state: str
    """The volume state."""
    volume_type: str
    """The volume type."""
    encrypted: bool
    """Indicates whether the volume is encrypted."""

    @session()
    def __init__(
        self,
        volume_id: str | None = None,
        region: str | None = None,
        data: dict[str, Any] | None = None,
        session: Session | None = None,
    ) -> None:
        """Initialize an EC2 volume description.

        :param volume_id: volume id. Used to retrieve volume data
            if data parameter is None
        :param region: region of the volume
        :param data: botocore data describing the volume. If None
            then data is fetched automatically using volume id and
            region
        """
        if data is None:
            assert volume_id is not None and region is not None and session is not None
            data = session.client("ec2", region).describe_volumes(
                InstanceIds=[volume_id]
            )["Volumes"][0]

        super().__init__(data, region)

    @property
    def attachments(self) -> list[VolumeAttachment]:
        """List attachments that involve that volume.

        :return: a list of attachments
        """
        return [VolumeAttachment(va, self.region) for va in self.data["Attachments"]]

    @property
    def create_time(self) -> datetime:
        """Return creation time.

        :return: time at which volume was created
        """
        return parse_date(self.data["CreateTime"])

    @session()
    def delete(self, session: Session | None = None) -> None:
        """Delete a volume."""
        assert session is not None
        session.client("ec2", self.region).delete_volume(VolumeId=self.volume_id)

    @classmethod
    @session()
    def ls(
        cls, filters: list[dict[str, Any]] | None = None, session: Session | None = None
    ) -> list[Volume]:
        """List user AMIs.

        :param filters: same as Filters parameters of describe_volumes
            (see botocore)
        :return a list of volumes
        """
        assert session is not None

        if filters is None:
            filters = []
        result = []
        for r in session.regions:
            c = session.client("ec2", r)
            region_result = c.describe_volumes(Filters=filters)
            for volume in region_result.get("Volumes", []):
                result.append(Volume(volume["VolumeId"], r, data=volume))
        return result


class Snapshot(EC2Element):
    PROPERTIES = {"Encrypted": "encrypted", "SnapshotId": "snapshot_id"}

    encrypted: bool
    """Indicates whether the snapshot is encrypted."""
    snapshot_id: str
    """The ID of the snapshot."""

    @session()
    def __init__(
        self,
        snapshot_id: str | None = None,
        region: str | None = None,
        data: dict[str, Any] | None = None,
        session: Session | None = None,
    ) -> None:
        """Initialize an EC2 snapshot description.

        :param snapshot_id: snapshot id. Used to retrieve snapshot data
            if data parameter is None
        :param region: region of the snapshot
        :param data: botocore data describing the snapshot. If None
            then data is fetched automatically using snapshot id and
            region
        """
        if data is None:
            assert (
                snapshot_id is not None and region is not None and session is not None
            )
            data = session.client("ec2", region).describe_snapshots(
                SnapshotIds=[snapshot_id]
            )["Snapshots"][0]

        super().__init__(data, region)

    @session()
    def delete(self, session: Session | None = None) -> None:
        """Delete a snapshot."""
        assert session is not None
        session.client("ec2", self.region).delete_snapshot(SnapshotId=self.snapshot_id)

    @classmethod
    @session()
    def ls(
        cls, filters: list[dict[str, Any]] | None = None, session: Session | None = None
    ) -> list[Snapshot]:
        """List snapshots.

        :param filters: same as Filters parameters of describe_snapshots
            (see botocore)
        :return a list of snaptshots
        """
        assert session is not None
        if filters is None:
            filters = []
        result = []
        for r in session.regions:
            c = session.client("ec2", r)
            region_result = c.describe_snapshots(OwnerIds=["self"], Filters=filters)
            for snapshot in region_result.get("Snapshots", []):
                result.append(Snapshot(snapshot["SnapshotId"], r, data=snapshot))
        return result


class NetworkInterface(EC2Element):
    """EC2 Network Interface."""

    def public_ip(self) -> str | None:
        """Return public ip.

        :return: return public ip or None
        """
        if "Association" in self.data:
            return self.data["Association"].get("PublicIp")
        else:
            return None
