from __future__ import annotations
import os
from typing import TYPE_CHECKING

from troposphere import cloudformation

from e3.aws import name_to_id
from e3.aws.troposphere import Construct
from e3.aws.troposphere import Stack


if TYPE_CHECKING:  # all: no cover
    from typing import Optional
    from troposphere import AWSHelperFn, AWSObject


class StackSet(Construct):
    """A CloudFormation service managed stack set."""

    def __init__(
        self,
        name: str,
        description: str,
        regions: list[str],
        ous: Optional[list[str]] = None,
        accounts: Optional[list[str]] = None,
        failure_tolerance_count: int = 0,
        max_concurrent_count: int = 1,
    ):
        """Initialize a CloudFormation service managed stack set.

        :param name: stack set name
        :param description: stack set description
        :param regions: list of regions where to deploy stack set stack instances
        :param ous: OrganizationalUnitIds for which to create stack instances
            in the specified Regions. Note that if both ous and accounts parameters
            are None then the stack set is deployed into the whole organisation
        :param accounts: list of accounts where to deploy stack set stack instances
        :param failure_tolerance_count: The number of accounts, per Region, for which
            the stackset deployment operation can fail before AWS CloudFormation stops
            the operation in that region
        :param max_conccurent_count: The maximum number of accounts in which to perform
            stackset deployment operations at one time. It is at most one more than the
            FailureToleranceCount.
        """
        self.name = name
        self.description = description
        self.stack = Stack(stack_name=f"{self.name}-stack", cfn_role_arn="stackset")
        self.template_filename = f"{self.name}-template.yaml"
        self.regions = regions
        self.ous = ous
        self.accounts = accounts

        self.operation_preferences = cloudformation.OperationPreferences(
            FailureToleranceCount=failure_tolerance_count,
            MaxConcurrentCount=max_concurrent_count,
        )

    def add(self, element: AWSObject | Construct | Stack) -> None:
        """Add resource to the stackset stack.

        :param element: resource to add to the stackset stack
        """
        self.stack.add(element)

    def add_condition(self, condition_name: str, condition: AWSHelperFn) -> None:
        """Add condition to stackset stack.

        :param condition_name: name of the condition to add
        :param condition: condition to add
        """
        self.stack.add_condition(condition_name, condition)

    def resources(self, stack: Stack) -> list[AWSObject]:
        """Return list of AWSObject associated with the construct."""
        stack_set_args = {
            "AutoDeployment": cloudformation.AutoDeployment(
                Enabled=True, RetainStacksOnAccountRemoval=False
            ),
            "CallAs": "SELF",
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "Description": self.description,
            "OperationPreferences": self.operation_preferences,
            "PermissionModel": "SERVICE_MANAGED",
            "StackSetName": self.name,
            "TemplateURL": (
                f"https://{stack.s3_bucket}.s3.amazonaws.com/{stack.s3_key}"
                f"{self.template_filename}"
            ),
        }

        if self.ous is not None or self.accounts is not None:
            stack_instances_group = []

            if self.ous is not None:
                stack_instances_group.append(
                    cloudformation.StackInstances(
                        DeploymentTargets=cloudformation.DeploymentTargets(
                            OrganizationalUnitIds=self.ous
                        ),
                        Regions=self.regions,
                    )
                )

            if self.accounts is not None:

                stack_instances_group.append(
                    cloudformation.StackInstances(
                        DeploymentTargets=cloudformation.DeploymentTargets(
                            Accounts=self.accounts
                        ),
                        Regions=self.regions,
                    )
                )

            stack_set_args["StackInstancesGroup"] = stack_instances_group
        return [cloudformation.StackSet(name_to_id(self.name), **stack_set_args)]

    def create_data_dir(self, root_dir: str) -> None:
        """Create data to be pushed to bucket used by cloudformation for resources."""
        template_path = os.path.join(root_dir, self.template_filename)
        with open(template_path, "w") as template_f:
            template_f.write(self.stack.body)
