from __future__ import annotations
from abc import ABC, abstractmethod
from itertools import chain
from troposphere import AWSObject, Template

from e3.aws import cfn, name_to_id, Session
from e3.aws.cfn.main import CFNMain
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # all: no cover
    from typing import Optional, Union
    from troposphere import And, Condition, Equals, If, Not, Or

    ConditionFunction = Union[And, Condition, Equals, If, Not, Or]


class Construct(ABC):
    """Represent one or multiple troposphere AWSObject.

    AWSObjects are accessible with resources attribute.
    """

    @abstractmethod
    def resources(self, stack: Stack) -> list[Union[AWSObject, Construct]]:
        """Return a list of troposphere AWSObject.

        Objects returned can be added to a troposphere template with
        add_resource Template method.

        :param stack: the stack that contains the construct
        """
        pass

    def cfn_policy_document(self, stack: Stack) -> PolicyDocument:
        """Return the IAM policy needed by CloudFormation to manage the stack.

        :param stack: the stack that contains the construct
        """
        return PolicyDocument([])

    def create_data_dir(self, root_dir: str) -> None:
        """Put data in root_dir before export to S3 bucket referenced by the stack.

        :param root_dir: local directory in which data should be stored. Data will
            be then uploaded to an S3 bucket accessible from the template. The
            target location is the one received by resources method. Note that
            the same root_dir is shared by all resources in your stack.
        """
        pass


class Stack(cfn.Stack):
    """Cloudformation stack using troposphere resources."""

    def __init__(
        self,
        stack_name: str,
        description: Optional[str] = None,
        cfn_role_arn: Optional[str] = None,
        deploy_session: Optional[Session] = None,
        dry_run: Optional[bool] = False,
        s3_bucket: Optional[str] = None,
        s3_key: Optional[str] = None,
    ) -> None:
        """Initialize Stack attributes.

        :param stack_name: stack name
        :param cfn_role_arn: role asssumed by cloud formation to create the stack
        :param deploy_session: AWS session to deploy non CloudFormation AWS
            resources (aka Assets)
        :param dry_run: True if the stack is not to be deployed.
        :param description: a description of the stack
        :param s3_bucket: s3 bucket used to store data needed by the stack
        :param s3_key: s3 prefix in s3_bucket in which data is stored
        """
        super().__init__(
            stack_name,
            cfn_role_arn=cfn_role_arn,
            description=description,
            s3_bucket=s3_bucket,
            s3_key=s3_key,
        )
        self.constructs: list[Construct | AWSObject] = []

        self.deploy_session = deploy_session
        self.dry_run = dry_run
        self.template = Template()

    def construct_to_objects(self, construct: Construct | AWSObject) -> list[AWSObject]:
        """Return list of AWS objects resources from a construct.

        :param construct: construct to list resources from
        """
        if isinstance(construct, AWSObject):
            return [construct]
        else:
            return list(
                chain.from_iterable(
                    [
                        self.construct_to_objects(el)
                        for el in construct.resources(stack=self)
                    ]
                )
            )

    def add(self, element: Union[AWSObject, Construct, Stack]) -> Stack:
        """Add a Construct or AWSObject to the stack.

        :param element: if a resource an AWSObject or Construct add the resource
             to the stack. If a stack merge its resources into the current stack.
        """
        if isinstance(element, Stack):
            constructs = element.constructs

        else:
            constructs = [element]

        # Add the new constructs (non expanded)
        self.constructs += constructs

        # Update the template
        resources = []
        for construct in constructs:
            resources.extend(self.construct_to_objects(construct))
        self.template.add_resource(resources)

        return self

    def add_condition(self, condition_name: str, condition: ConditionFunction) -> None:
        """Add condition to stack template.

        :param condition_name: name of the condition to add
        :param condition: condition to add
        """
        self.template.add_condition(condition_name, condition)

    def cfn_policy_document(self) -> PolicyDocument:
        """Return stack necessary policy document for CloudFormation."""
        result = PolicyDocument([])
        for construct in self.constructs:
            if isinstance(construct, Construct):
                result += construct.cfn_policy_document(stack=self)

        return result

    def __getitem__(self, resource_name: str) -> AWSObject:
        """Return AWSObject associated with resource_name.

        :param resource_name: name of the resource to retrieve
        """
        return self.template.resources[name_to_id(resource_name)]

    def export(self) -> dict:
        """Export stack as dict.

        :return: a dict that can be serialized as YAML to produce a template
        """
        result = self.template.to_dict()
        if self.description is not None:
            result["Description"] = self.description
        return result

    def create_data_dir(self, root_dir: str) -> None:
        """Populate root_dir with data needed by all constructs in the stack.

        :param root_dir: the local directory in which to store the data
        """
        for construct in self.constructs:
            if isinstance(construct, Construct):
                construct.create_data_dir(root_dir)


class CFNProjectMain(CFNMain):
    """CFNMain with default value and self initializing its stack.

    This facilitates the deployment of mono stack projects with deployment and
    CloudFormation roles named respectively cfn-user/CFNAllowDeployOf<stack_name>
    and cfn-service/CFNServiceRoleFor<stack_name>.
    """

    def __init__(
        self,
        name: str,
        account_id: str,
        stack_description: str,
        s3_bucket: str,
        regions: list[str],
    ) -> None:
        """
        Initialize a CFNProjectMain instance.

        :param name: name of the project
        :param account_id: id of the account where to deploy the project
        :param stack_description: description of the stack to deploy
        :param s3_bucket: see CFNMain
        :param regions: see CFNMain
        """
        super().__init__(
            regions=regions,
            s3_bucket=s3_bucket,
            s3_key=name,
            assume_role=(
                f"arn:aws:iam::{account_id}:role/cfn-user/CFNAllowDeployOf{name}",
                f"Deploy{name}Session",
            ),
        )
        self.stack = Stack(
            name,
            cfn_role_arn=f"arn:aws:iam::{account_id}:role/cfn-service/CFNServiceRoleFor{name}",
            description=stack_description,
            s3_bucket=s3_bucket,
            s3_key=self.s3_data_key,
        )

    def add(self, element: AWSObject | Construct | Stack) -> Stack:
        """Add resource to project's stack.

        :param element: resource to add to the stack.
        """
        return self.stack.add(element)
