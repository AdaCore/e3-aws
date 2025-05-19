"""Provide fixtures for e3 aws tests."""

from __future__ import annotations
from typing import TYPE_CHECKING
import pytest

if TYPE_CHECKING:
    from pytest import MonkeyPatch


@pytest.fixture(autouse=True)
def set_ci(monkeypatch: MonkeyPatch) -> None:
    """Toggle on CI by default.

    That variable is set by GitLab and may lead to different local test results
    if not set.
    """
    monkeypatch.setenv("CI", "true")
