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
    ):
        """Initialize a CloudFormation service managed stack set.

        :param name: stack set name
        :param description: stack set description
        :param regions: list of regions where to deploy stack set stack instances
        :param ous: OrganizationalUnitIds for which to create stack instances
            in the specified Regions.
        """
        self.name = name
        self.description = description
        self.stack = Stack(stack_name=f"{self.name}-stack", cfn_role_arn="stackset")
        self.template_filename = f"{self.name}-template.yaml"
        self.regions = regions
        self.organizational_units = ous

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
        return [
            cloudformation.StackSet(
                name_to_id(self.name),
                AutoDeployment=cloudformation.AutoDeployment(
                    Enabled=True, RetainStacksOnAccountRemoval=False
                ),
                CallAs="SELF",
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Description=self.description,
                PermissionModel="SERVICE_MANAGED",
                StackSetName=self.name,
                StackInstancesGroup=[
                    cloudformation.StackInstances(
                        DeploymentTargets=cloudformation.DeploymentTargets(
                            OrganizationalUnitIds=self.organizational_units
                        ),
                        Regions=self.regions,
                    )
                ],
                TemplateURL=(
                    f"https://{stack.s3_bucket}.s3.amazonaws.com/{stack.s3_key}"
                    f"{self.template_filename}"
                ),
            )
        ]

    def create_data_dir(self, root_dir: str) -> None:
        """Create data to be pushed to bucket used by cloudformation for resources."""
        template_path = os.path.join(root_dir, self.template_filename)
        with open(template_path, "w") as template_f:
            template_f.write(self.stack.body)
