from __future__ import annotations
from typing import TYPE_CHECKING
from troposphere import cloudwatch, GetAtt, Ref

from e3.aws import name_to_id
from e3.aws.troposphere import Construct

if TYPE_CHECKING:
    from troposphere import AWSObject
    from e3.aws.troposphere import Stack


class Alarm(Construct):
    """A CloudWatch Alarm."""

    def __init__(
        self,
        name: str,
        description: str,
        comparison_operator: str,
        evaluation_periods: int,
        actions: list[str | Ref] | None = None,
        dimensions: dict[str, str | Ref] | None = None,
        metric_name: str | None = None,
        namespace: str | None = None,
        period: int | None = None,
        statistic: str | None = None,
        threshold: float | None = None,
    ):
        """Initialize an AWS CloudWatch alarm.

        :param name: alarm name
        :param description: the description of the alarm
        :param comparison_operator: the arithmetic operation to use when
            comparing the specified statistic and threshold
        :param evaluation_periods: the number of periods over which data is
            compared to the specified threshold
        :param actions: the list of actions to execute when this alarm transitions
            into an ALARM state from any other state
        :param dimensions: the dimensions for the metric associated with the alarm
        :param metric_name: the name of the metric associated with the alarm
        :param namespace: the namespace of the metric associated with the alarm
        :param period: the period, in seconds, over which the statistic is applied
        :param statistic: the statistic for the metric associated with the alarm,
            other than percentile. For percentile statistics, use ExtendedStatistic
        :param threshold: the value to compare with the specified statistic
        """
        self.name = name
        self.description = description
        self.comparison_operator = comparison_operator
        self.evaluation_periods = evaluation_periods
        self.actions = actions
        self.dimensions = dimensions
        self.metric_name = metric_name
        self.namespace = namespace
        self.period = period
        self.statistic = statistic
        self.threshold = threshold

    @property
    def arn(self) -> GetAtt:
        """Arn of the CloudWatch alarm."""
        return GetAtt(name_to_id(self.name), "Arn")

    @property
    def ref(self) -> Ref:
        return Ref(name_to_id(self.name))

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        params = {
            "AlarmName": self.name,
            "AlarmDescription": self.description,
            "ComparisonOperator": self.comparison_operator,
            "EvaluationPeriods": self.evaluation_periods,
        }

        if self.actions is not None:
            params["AlarmActions"] = self.actions

        if self.dimensions is not None:
            params["Dimensions"] = [
                cloudwatch.MetricDimension(Name=k, Value=v)
                for k, v in self.dimensions.items()
            ]

        if self.metric_name is not None:
            params["MetricName"] = self.metric_name

        if self.namespace is not None:
            params["Namespace"] = self.namespace

        if self.period is not None:
            params["Period"] = self.period

        if self.statistic is not None:
            params["Statistic"] = self.statistic

        if self.threshold is not None:
            params["Threshold"] = self.threshold

        return [cloudwatch.Alarm(name_to_id(self.name), **params)]
