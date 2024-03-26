from __future__ import annotations
from typing import TYPE_CHECKING
from enum import Enum
from troposphere import dynamodb, GetAtt, Ref, Tags
from troposphere.dynamodb import PointInTimeRecoverySpecification

from e3.aws import name_to_id
from e3.aws.troposphere import Construct

if TYPE_CHECKING:
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack


class ProjectionType(Enum):
    """Allowed projection types for dynamodb secondary indexes.

    - KEYS_ONLY - projection type chosen when only the index and
        primary keys are to be projected into the index.
    - INCLUDE - projection type chosen when in addition to the
        attributes described in KEYS_ONLY, the secondary index
        includes other non-key attributes that you specify.
    - ALL - projection type chosen when all of the table attributes
        are projected into the index
    """

    KEYS_ONLY = "KEYS_ONLY"
    INCLUDE = "INCLUDE"
    ALL = "ALL"

    def __str__(self):
        return str(self.value)


KEYS_ONLY_PROJECTION = ProjectionType.KEYS_ONLY
INCLUDE_PROJECTION = ProjectionType.INCLUDE
ALL_PROJECTION = ProjectionType.ALL


class GlobalSecondaryIndex(object):
    """Global Secondary Index e3-aws abstraction class."""

    def __init__(
        self,
        index_name: str,
        key_schema: dict,
        projection_type: ProjectionType,
        non_key_attributes: list[str] | None = None,
        read_capacity_units: int | None = None,
        write_capacity_units: int | None = None,
    ):
        """Initialize a Global Secondary index.

        :param index_name: name of the global secondary index
        :param key_schema: specifies the attributes of the key
            schema for a global secondary index,
        :param projection_type: type of projection on the global
            secondary index
        :param non_key_attributes: the non key attributes that will be
            projected, defaults to None
        :param read_capacity_units: the maximum number of strongly
        consistent reads consumed per second before DynamoDB returns a
            ThrottlingException (default 10)
        :param write_capacity_units: the maximum number of writes
            consumed per second before DynamoDB returns a
            ThrottlingException (default 10)
        """
        self.index_name = index_name
        self.key_schema = key_schema
        self.projection_type = projection_type
        self.non_key_attributes = non_key_attributes
        if self.projection_type is INCLUDE_PROJECTION:
            assert (
                self.non_key_attributes is not None
            ), "non key attributes parameter is required when the projection "
            "type is INCLUDE"
        self.read_capacity_units = read_capacity_units
        self.write_capacity_units = write_capacity_units


class Table(Construct):
    """A DynamoDB Table."""

    def __init__(
        self,
        name: str,
        attribute_definitions: dict[str, str],
        key_schema: dict[str, str],
        global_secondary_indexes: list[GlobalSecondaryIndex] | None = None,
        tags: dict[str, str] | None = None,
        point_in_time_recovery_enabled: bool | None = True,
        billing_mode: str | None = None,
        read_capacity_units: int | Ref | None = None,
        write_capacity_units: int | Ref | None = None,
        time_to_live_attribute_name: str | None = None,
        time_to_live_enabled: bool | None = None,
        stream_enabled: bool | None = None,
        stream_view_type: str | None = None,
    ):
        """Initialize an AWS DynamoDB table.

        :param name: table name
        :param attribute_definitions: dictionary for attribute definitions, keys are
            attributes names and values are DynamoDB attributes types
        :param key_schema: specifies the attributes that make up the primary key for
            the table
        : param global_secondary_indexes: a list of the Global secondary indexes to
            be created on the table. Up to 20 global secondary indexes can be created.
        :param tags: dictionary of tags to apply to this resource
        :param point_in_time_recovery_enabled: indicates whether point in time
            recovery is enabled (true) or disabled (false) on the table (default True)
        :param billing_mode: specify how you are charged for read and write throughput
            and how you manage capacity
        :param read_capacity_units: the maximum number of strongly consistent reads
            consumed per second before DynamoDB returns a ThrottlingException
            (default 10)
        :param write_capacity_units: the maximum number of writes consumed per second
            before DynamoDB returns a ThrottlingException (default 10)
        :param time_to_live_attribute_name: the name of the TTL attribute used to store
            the expiration time for items in the table
        :param time_to_live_enabled: indicates whether TTL is to be enabled (true) or
            disabled (false) on the table
        :param stream_enabled: indicates whether DynamoDB Streams is enabled (true)
            or disabled (false) on the table
        :param stream_view_type: when an item in the table is modified, StreamViewType
            determines what information is written to the stream for this table
            (default NEW_IMAGE)
        """
        self.name = name
        self.attribute_definitions = attribute_definitions
        self.key_schema = key_schema
        self.global_secondary_indexes = global_secondary_indexes
        self.tags = tags
        self.point_in_time_recovery_enabled = point_in_time_recovery_enabled
        self.billing_mode = billing_mode
        self.read_capacity_units = read_capacity_units
        self.write_capacity_units = write_capacity_units
        self.time_to_live_attribute_name = time_to_live_attribute_name
        self.time_to_live_enabled = time_to_live_enabled
        self.stream_enabled = stream_enabled
        self.stream_view_type = stream_view_type

    @property
    def arn(self) -> GetAtt:
        """Arn of the DynamoDB table."""
        return GetAtt(name_to_id(self.name), "Arn")

    @property
    def ref(self) -> Ref:
        return Ref(name_to_id(self.name))

    @property
    def stream_arn(self) -> GetAtt:
        """StreamArn of the DynamoDB table."""
        return GetAtt(name_to_id(self.name), "StreamArn")

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        params: dict = {
            "TableName": self.name,
            "AttributeDefinitions": [
                dynamodb.AttributeDefinition(AttributeName=k, AttributeType=v)
                for k, v in self.attribute_definitions.items()
            ],
            "KeySchema": [
                dynamodb.KeySchema(AttributeName=k, KeyType=v)
                for k, v in self.key_schema.items()
            ],
        }

        if self.global_secondary_indexes:
            params["GlobalSecondaryIndexes"] = []
            for gsi in self.global_secondary_indexes:
                projection_param: dict = {"ProjectionType": str(gsi.projection_type)}
                if gsi.projection_type is INCLUDE_PROJECTION:
                    projection_param["NonKeyAttributes"] = gsi.non_key_attributes

                params["GlobalSecondaryIndexes"].append(
                    dynamodb.GlobalSecondaryIndex(
                        IndexName=gsi.index_name,
                        KeySchema=[
                            dynamodb.KeySchema(AttributeName=k, KeyType=v)
                            for k, v in gsi.key_schema.items()
                        ],
                        Projection=dynamodb.Projection(**projection_param),
                        ProvisionedThroughput=dynamodb.ProvisionedThroughput(
                            ReadCapacityUnits=(
                                gsi.read_capacity_units
                                if gsi.read_capacity_units is not None
                                else 10
                            ),
                            WriteCapacityUnits=(
                                gsi.write_capacity_units
                                if self.write_capacity_units is not None
                                else 10
                            ),
                        ),
                    )
                )

        if self.tags is not None:
            params["Tags"] = Tags(**self.tags)

        if self.point_in_time_recovery_enabled:
            params["PointInTimeRecoverySpecification"] = (
                PointInTimeRecoverySpecification(PointInTimeRecoveryEnabled=True)
            )

        if self.billing_mode is not None:
            params["BillingMode"] = self.billing_mode

        params["ProvisionedThroughput"] = dynamodb.ProvisionedThroughput(
            ReadCapacityUnits=(
                self.read_capacity_units if self.read_capacity_units is not None else 10
            ),
            WriteCapacityUnits=(
                self.write_capacity_units
                if self.write_capacity_units is not None
                else 10
            ),
        )

        if self.time_to_live_enabled is not None:
            assert (
                self.time_to_live_attribute_name is not None
            ), "time_to_live_attribute_name should be set"
            params["TimeToLiveSpecification"] = dynamodb.TimeToLiveSpecification(
                AttributeName=self.time_to_live_attribute_name,
                Enabled=self.time_to_live_enabled,
            )

        if self.stream_enabled:
            params["StreamSpecification"] = dynamodb.StreamSpecification(
                StreamViewType=(
                    self.stream_view_type
                    if self.stream_view_type is not None
                    else "NEW_IMAGE"
                )
            )

        return [dynamodb.Table(name_to_id(self.name), **params)]
