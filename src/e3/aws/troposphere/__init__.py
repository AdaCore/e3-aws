from __future__ import annotations
from abc import ABC, abstractmethod
from troposphere import AWSObject, Template
from e3.aws import cfn, name_to_id

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Dict, List, Optional, Union


class Property(ABC):
    """Property abstract class.

    Define an intermediate class that can be used to build a Construct.
    Construct use property by accessing their as_dict attribute that should
    correspond to a valid troposphere property definition.
    """

    @property
    @abstractmethod
    def as_dict(self) -> dict:
        """Return dictionary representation of the property."""
        pass


class Construct(ABC):
    """Represent one or multiple troposphere AWSObject.

    AWSObjects are accessible with resources attribute.
    """

    @property
    @abstractmethod
    def resources(self) -> List[AWSObject]:
        """Return a list of troposphere AWSObject.

        Objects returned can be added to a troposphere template with
        add_resource Template method.
        """
        pass


class Stack(cfn.Stack, Construct):
    """Cloudformation stack using troposphere resources."""

    def __init__(
        self,
        stack_name: str,
        cfn_role_arn: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        """Initialize Stack attributes.

        :param stack_name: stack name
        :param cfn_role_arn: role asssumed by cloud formation to create the stack
        :param description: a description of the stack
        """
        self.resources = {}
        super().__init__(
            stack_name,
            cfn_role_arn=cfn_role_arn,
            description=description,
        )
        self.template: Template = Template()

    def add(self, element: Union[AWSObject, Construct]) -> Stack:
        """Add a Construct or AWSObject to the stack.

        :param element: if a resource an AWSObject or Construct add the resource
             to the stack. If a stack merge its resources into the current stack.
        """
        resources = []

        if isinstance(element, Construct):
            resources = element.resources

        if isinstance(element, AWSObject):
            resources = [element]

        self.template.add_resource(resources)

        return self

    @property
    def resources(self) -> List[AWSObject]:
        """Return stack resources."""
        return self.template.resources

    @resources.setter
    def resources(self, value: Dict[str]) -> None:
        """Empty setter needed when calling cfn.Stack init method."""
        pass

    def __getitem__(self, resource_name: str) -> AWSObject:
        """Return AWSObject associated with resource_name.

        :param resource_name: name of the resource to retrieve
        """
        return self.template.resources[name_to_id(resource_name)]

    def export(self) -> dict:
        """Export stack as dict.

        :return: a dict that can be serialized as YAML to produce a template
        """
        return self.template.to_dict()
