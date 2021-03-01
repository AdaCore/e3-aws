"""Provide PolicyDocument class."""

from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List
    from e3.aws.troposphere.iam.policy_statement import PolicyStatement


@dataclass
class PolicyDocument:
    """Define a policy document.

    :param statements: policy statements to add to the policy
    :param version: version of language syntax rules that are to be used to
        process the policy
    """

    statements: List[PolicyStatement]
    version: str = "2012-10-17"

    def __add__(self, other: PolicyDocument) -> PolicyDocument:
        """Return a new policy document combining statements from self and other.

        :param other: Other PolicyDocument from which to add statements
        """
        return PolicyDocument(statements=self.statements + other.statements)

    def __iadd__(self, other: PolicyDocument) -> PolicyDocument:
        self.statements += other.statements
        return self

    @property
    def as_dict(self) -> dict:
        """Return dictionary representation of the PolicyDocument."""
        policy_document = {
            "Version": self.version,
            "Statement": [statement.as_dict for statement in self.statements],
        }

        return policy_document
