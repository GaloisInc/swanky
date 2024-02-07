from collections import defaultdict
from typing import DefaultDict, Dict, FrozenSet, Set

import click
import rich

from etc import ROOT
from etc.lint import LintResult


def lint_codeowners_file(ctx: click.Context) -> LintResult:
    """
    Lint .gitlab/CODEOWNERS

    Check that all CODEOWNERS paths exist
    Check that all CODEOWNERS entries for folders have one entry with a final slash and one without
        See https://docs.gitlab.com/ee/user/project/codeowners/#user-or-group-not-shown-when-viewing-code-owners-for-a-directory
    """
    any_errors = False
    current_section = ""
    contents: DefaultDict[str, Dict[str, FrozenSet[str]]] = defaultdict(dict)
    for i, line in enumerate((ROOT / ".gitlab/CODEOWNERS").read_text().splitlines()):
        line = line.strip()
        lineno = i + 1
        if line.startswith("#"):
            # It's a comment. (See this line as an example!)
            continue
        if line.startswith("["):
            # This is a section header
            current_section = line[1:].split("]")[0]
            continue
        if line == "":
            # The line is blank
            continue
        # If we get here, then the line defines a code ownership rule.
        path_txt, *owners_list = line.split()
        owners = frozenset(owners_list)
        if path_txt[0] != "/":
            any_errors = True
            rich.print(
                f"At line {lineno} of CODEOWNERS, the file path doesn't start with a slash."
            )
            continue
        path = ROOT / path_txt[1:]
        if not path.exists():
            any_errors = True
            rich.print(f"At line {lineno} of CODEOWNERS {path_txt} does not exist")
        contents[current_section][path_txt] = owners
    for section, entries in contents.items():
        for path_txt, owners in entries.items():
            path = ROOT / path_txt[1:]
            if path.is_dir():
                not_entry = path_txt[:-1] if path_txt.endswith("/") else path_txt + "/"
                not_entry_owners = entries.get(not_entry, None)
                if not_entry_owners is None or not_entry_owners != owners:
                    any_errors = True
                    section_label = (
                        "the global section"
                        if section == ""
                        else f"Section {repr(section)}"
                    )
                    if not_entry_owners is None:
                        rich.print(
                            f"{repr(path_txt)} in {section_label} is missing a corresponding {repr(not_entry)}"
                        )
                    else:
                        rich.print(
                            f"{repr(path_txt)} in {section_label} has different owners than {repr(not_entry)}"
                        )

    if any_errors:
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS
