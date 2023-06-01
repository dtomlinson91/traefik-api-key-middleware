from __future__ import annotations

import contextlib
import importlib
import os
import pathlib
import re
import shutil
import sys
from io import StringIO
from typing import Optional

from duty import duty

PACKAGE_NAME = "traefik-api-key-middleware"
REPO_URL = "https://github.com/dtomlinson91/traefik-api-key-middleware"


@duty
def changelog(ctx, planned_release: Optional[str] = None, previous_release: Optional[str] = None):
    """
    Generate a changelog with git-cliff.

    Args:
        ctx: The context instance (passed automatically).
        planned_release (str, optional): The planned release version. Example: v1.0.2
        previous_release (str, optional): The previous release version. Example: v1.0.1
    """
    generated_changelog: str = ctx.run(["git", "cliff", "-u", "-t", planned_release, "-s", "header"])[:-1]
    if previous_release is not None:
        generated_changelog: list = generated_changelog.splitlines()
        generated_changelog.insert(
            1,
            f"<small>[Compare with {previous_release}]({REPO_URL}/compare/{previous_release}...{planned_release})</small>",
        )
        generated_changelog: str = "\n".join(list(generated_changelog)) + "\n"
    new_changelog = []

    changelog_file = pathlib.Path(".") / "CHANGELOG.md"
    with changelog_file.open("r", encoding="utf-8") as changelog_contents:
        all_lines = changelog_contents.readlines()
        for line_string in all_lines:
            regex_string = re.search(r"(<!-- marker -->)", line_string)
            new_changelog.append(line_string)
            if isinstance(regex_string, re.Match):
                new_changelog.append(generated_changelog)
    with changelog_file.open("w", encoding="utf-8") as changelog_contents:
        changelog_contents.writelines(new_changelog)
