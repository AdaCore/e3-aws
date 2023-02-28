from __future__ import annotations

from troposphere import Ref
from e3.aws.troposphere import Stack
from e3.aws.troposphere.cloudwatch import Alarm


EXPECTED_ALARM_DEFAULT_TEMPLATE = {
    "Myalarm": {
        "Properties": {
            "AlarmDescription": "Some description",
            "AlarmName": "myalarm",
            "ComparisonOperator": "LessThanThreshold",
            "EvaluationPeriods": 2,
            "Statistic": "Sum",
        },
        "Type": "AWS::CloudWatch::Alarm",
    },
}


EXPECTED_ALARM_TEMPLATE = {
    "Myalarm": {
        "Properties": {
            **EXPECTED_ALARM_DEFAULT_TEMPLATE["Myalarm"]["Properties"],
            **{
                "AlarmActions": ["StrAction", {"Ref": "RefAction"}],
                "Dimensions": [
                    {"Name": "StrDimensionValue", "Value": "DimensionValue"},
                    {"Name": "RefDimensionValue", "Value": {"Ref": "DimensionValue"}},
                ],
                "MetricName": "Invocations",
                "Namespace": "AWS/Lambda",
                "Period": 300,
                "Threshold": 1.0,
            },
        },
        "Type": "AWS::CloudWatch::Alarm",
    },
}


def test_alarm_default(stack: Stack) -> None:
    """Test default Alarm creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        Alarm(
            name="myalarm",
            description="Some description",
            comparison_operator="LessThanThreshold",
            evaluation_periods=2,
            statistic="Sum",
        )
    )
    assert stack.export()["Resources"] == EXPECTED_ALARM_DEFAULT_TEMPLATE


def test_alarm(stack: Stack) -> None:
    """Test Alarm creation."""
    stack.s3_bucket = "cfn_bucket"
    stack.s3_key = "templates/"
    stack.add(
        Alarm(
            name="myalarm",
            description="Some description",
            comparison_operator="LessThanThreshold",
            evaluation_periods=2,
            actions=["StrAction", Ref("RefAction")],
            dimensions={
                "StrDimensionValue": "DimensionValue",
                "RefDimensionValue": Ref("DimensionValue"),
            },
            metric_name="Invocations",
            namespace="AWS/Lambda",
            period=300,
            statistic="Sum",
            threshold=1.0,
        )
    )
    assert stack.export()["Resources"] == EXPECTED_ALARM_TEMPLATE
