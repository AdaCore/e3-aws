"""Provide CloudFormation EC2 user data resources."""

from __future__ import annotations

from email.contentmanager import raw_data_manager
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart

from e3.aws.cfn import Base64, Sub

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

CFN_INIT_STARTUP_SCRIPT = """#!/bin/sh
sed -i 's/scripts-user$/[scripts-user, always]/' /etc/cloud/cloud.cfg
sed -i 's/scripts_user$/[scripts_user, always]/' /etc/cloud/cloud.cfg
${Cfninit} -v --stack ${AWS::StackName} \\
                --region ${AWS::Region} \\
                --resource ${Resource} \\
                --configsets ${Config} ${CfninitOptions}\n\n"""


CFN_INIT_STARTUP_SCRIPT_WIN = (
    "C:\\ProgramData\\Amazon\\EC2-Windows\\"
    "Launch\\Scripts\\InitializeInstance.ps1 -schedule \n"
    "${Cfninit} -v --stack ${AWS::StackName} --region "
    "${AWS::Region} --resource ${Resource} --configsets ${Config} "
    "${CfninitOptions}\n\n"
)


class UserData:
    """EC2 Instance user data."""

    def __init__(self) -> None:
        """Initialize user data."""
        self.parts: list[tuple[str, str, str]] = []
        self.variables: dict[str, Any] = {}

    def add(
        self,
        kind: str,
        content: str,
        name: str,
        variables: dict[str, Any] | None = None,
    ) -> None:
        """Add an entry in the user data.

        :param kind: MIME subtype (maintype is always text)
        :param content: the content associated with that value
        :param name: name of the entry (aka filename)
        """
        if variables is not None:
            self.variables.update(variables)
        self.parts.append((name, kind, content))

    @property
    def properties(self) -> Base64:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        # This is important to keep the boundary static in order to avoid
        # spurious instance reboots.
        multi_part = MIMEMultipart(
            boundary="-_- :( :( /o/ Static User Data Boundary /o/ :) :) -_-"
        )
        for name, kind, part in self.parts:
            mime_part = EmailMessage()
            raw_data_manager.set_content(mime_part, part, subtype=kind, filename=name)
            multi_part.attach(mime_part)
        return Base64(Sub(multi_part.as_string(), self.variables))


class WinUserData:
    """EC2 Windows Instance user data."""

    def __init__(self) -> None:
        """Initialize user data."""
        self.parts: list[tuple[str, str]] = []
        self.variables: dict[str, Any] = {}

    def add(
        self, kind: str, content: str, variables: dict[str, Any] | None = None
    ) -> None:
        """Add an entry in the user data.

        :param kind: script/powershell/persist
        :param content: the content associated with that value
        """
        if variables is not None:
            self.variables.update(variables)
        self.parts.append((kind, content))

    @property
    def properties(self) -> Base64:
        """Serialize the object as a simple dict.

        Can be used to transform to CloudFormation Yaml format.
        """
        props = ""
        for kind, part in self.parts:
            props += f"<{kind}>\n{part}\n</{kind}>"
        return Base64(Sub(props, self.variables))
