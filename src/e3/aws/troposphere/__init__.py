from __future__ import annotations
from abc import ABC, abstractmethod
from tempfile import TemporaryDirectory
from itertools import chain
from troposphere import AWSObject, Output, Template, Parameter
from collections import deque
import logging

from e3.aws import cfn, name_to_id, Session
from e3.aws.cfn.main import CFNMain
from e3.aws.troposphere.iam.policy_document import PolicyDocument
from typing import TYPE_CHECKING


if TYPE_CHECKING:  # all: no cover
    from typing import Union, Any
    from collections.abc import Iterable
    from troposphere import And, Condition, Equals, If, Not, Or

    ConditionFunction = Union[And, Condition, Equals, If, Not, Or]


class Construct(ABC):
    """Represent one or multiple troposphere AWSObject.

    AWSObjects are accessible with resources attribute.
    """

    @abstractmethod
    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
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

    def create_data_dir(self, root_dir: str) -> None:  # noqa: B027
        """Put data in root_dir before export to S3 bucket referenced by the stack.

        :param root_dir: local directory in which data should be stored. Data will
            be then uploaded to an S3 bucket accessible from the template. The
            target location is the one received by resources method. Note that
            the same root_dir is shared by all resources in your stack.
        """
        pass


class Asset(Construct):
    """Generic asset.

    Assets are local files or directories that are uploaded to S3 and that can be
    referenced by other resources. For example, an asset might be a directory
    that contains the handler code for an AWS Lambda function. Assets can represent
    any artifact that the app needs to operate.

    Each asset insert an additional parameter to the CloudFormation template, that
    can be used by other resources, with the intrinsic function Fn::Sub, to
    reference the S3 key of the asset.
    """

    def __init__(self, name: str) -> None:
        """Initialize Asset.

        :param name: the logical name for CloudFormation
        """
        self.name = name
        self.s3_key_parameter_name = f"{self.name}S3Key"

    @property
    @abstractmethod
    def s3_key(self) -> str | None:
        """Return the S3 key of this asset.

        It may return None if the S3 key is not yet known.
        """
        ...

    @property
    def s3_key_parameter(self) -> str:
        """Return the parameter that stores the S3 key.

        The Default value is omitted if the S3 key is not yet known.
        """
        params: dict[str, Any] = {}
        s3_key = self.s3_key
        if s3_key is not None:
            params["Default"] = s3_key

        return Parameter(
            self.s3_key_parameter_name,
            Type="String",
            Description=f"S3 key of asset {self.name}",
            **params,
        )

    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
        """Return no resources."""
        # Add the parameter during template creation even if the S3 key may not
        # be known yet. This is useful if creating a stack from code, so that
        # the exported template contains the parameter
        stack.add_parameter(self.s3_key_parameter)
        return []

    @abstractmethod
    def create_assets_dir(self, root_dir: str) -> None:  # noqa: B027
        """Put assets in root_dir before export to S3 bucket referenced by the stack.

        :param root_dir: local directory in which assets should be stored. Assets will
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
        description: str | None = None,
        cfn_role_arn: str | None = None,
        deploy_session: Session | None = None,
        dry_run: bool | None = False,
        s3_bucket: str | None = None,
        s3_key: str | None = None,
        s3_assets_key: str | None = None,
        version: str | None = None,
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
        :param s3_assets_key: s3 prefix in s3_bucket in which assets are stored
        :param version: template format version
        """
        super().__init__(
            stack_name,
            cfn_role_arn=cfn_role_arn,
            description=description,
            s3_bucket=s3_bucket,
            s3_key=s3_key,
        )
        self.constructs: list[Construct | AWSObject] = []
        self.assets: dict[str, Asset] = {}

        self.deploy_session = deploy_session
        self.dry_run = dry_run
        self.version = version
        self.s3_assets_key = s3_assets_key
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

    def add(self, element: AWSObject | Construct | Stack) -> Stack:
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

        # Update the template with AWSObjects.
        # Convert Constructs to AWSObjects | Constructs recursively
        resources = []
        constructs_to_objects = deque(constructs)
        while constructs_to_objects:
            construct = constructs_to_objects.pop()
            if isinstance(construct, AWSObject):
                resources.append(construct)
            else:
                # Special case to keep track of Assets and generate parameters
                # for the S3 keys
                if isinstance(construct, Asset):
                    self.add_parameter(construct.s3_key_parameter)
                    self.assets[construct.name] = construct

                constructs_to_objects.extend(construct.resources(stack=self))

        self.template.add_resource(resources)

        return self

    def extend(self, elements: Iterable[AWSObject | Construct | Stack]) -> Stack:
        """Add multiple Construct or AWSObject to the stack.

        :param elements: see Stack.add
        """
        for el in elements:
            self.add(el)

        return self

    def add_parameter(self, parameter: Parameter | list[Parameter]) -> None:
        """Add parameters to stack template.

        :param parameter: parameter to add to the template
        """
        if not isinstance(parameter, list):
            parameter = [parameter]

        for param in parameter:
            if param.title in self.template.parameters:
                self.template.parameters[param.title] = param
            else:
                self.template.add_parameter(param)

    def add_output(self, output: Output | list[Output]) -> None:
        """Add outputs to stack template.

        :param output: output to add to the template
        """
        self.template.add_output(output)

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
        result["AWSTemplateFormatVersion"] = (
            "2010-09-09" if self.version is None else self.version
        )
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
        deploy_branch: str | None = None,
    ) -> None:
        """
        Initialize a CFNProjectMain instance.

        :param name: name of the project
        :param account_id: id of the account where to deploy the project
        :param stack_description: description of the stack to deploy
        :param s3_bucket: see CFNMain
        :param regions: see CFNMain
        :param deploy_branch: git branch the script is allowed to deploy from
        """
        super().__init__(
            regions=regions,
            s3_bucket=s3_bucket,
            s3_key=name,
            assume_read_role=(
                f"arn:aws:iam::{account_id}:role/cfn-user/CFNAllowReadOf{name}",
                f"Read{name}Session",
            ),
            assume_role=(
                f"arn:aws:iam::{account_id}:role/cfn-user/CFNAllowDeployOf{name}",
                f"Deploy{name}Session",
            ),
            deploy_branch=deploy_branch,
        )
        self.stack = Stack(
            name,
            cfn_role_arn=f"arn:aws:iam::{account_id}:role/cfn-service/CFNServiceRoleFor{name}",
            description=stack_description,
            s3_bucket=s3_bucket,
            s3_key=self.s3_data_key,
            s3_assets_key=self.s3_assets_key,
        )
        self.gen_assets_dir: str | None = None

    def add(self, element: AWSObject | Construct | Stack) -> Stack:
        """Add resource to project's stack.

        :param element: resource to add to the stack.
        """
        return self.stack.add(element)

    def extend(self, elements: list[AWSObject | Construct | Stack]) -> Stack:
        """Add resources to project's stack.

        :param elements: resources to add to the stack.
        """
        return self.stack.extend(elements)

    def _upload_stack(self, stack: cfn.Stack) -> None:
        """See CFNMain."""
        # Nothing to upload if there is no S3 bucket or S3 assets key set
        if self.s3_bucket is not None and self.s3_assets_key is not None:
            # Upload assets to S3 first
            if self.aws_env:
                s3 = self.aws_env.client("s3")
            else:
                s3 = None
                logging.warning(
                    "no aws session, won't be able to check if assets exist "
                    "in the bucket"
                )

            assert self.gen_assets_dir is not None
            self._upload_dir(
                root_dir=self.gen_assets_dir,
                s3_bucket=self.s3_bucket,
                s3_key=self.s3_assets_key,
                s3_client=s3,
                check_exists=True,
            )

        # Upload the rest
        super()._upload_stack(stack)

    def execute_for_stack(
        self, stack: cfn.Stack, aws_env: Session | None = None
    ) -> int:
        """See CFNMain."""
        # Set the directory where to generate assets
        with TemporaryDirectory() as tmpd:
            self.gen_assets_dir = tmpd

            # Create the assets directory
            assert self.args is not None
            if isinstance(stack, Stack) and self.args.command in [
                "show",
                "push",
                "update",
            ]:
                for asset in stack.assets.values():
                    # Populate the assets directory
                    asset.create_assets_dir(root_dir=tmpd)

                    # Add a parameter to the stack with the known S3 key of the
                    # asset
                    stack.add_parameter(asset.s3_key_parameter)

            try:
                # Execute the command for the stack
                return super().execute_for_stack(stack=stack, aws_env=aws_env)
            finally:
                # Unset the assets directory
                self.gen_assets_dir = None
