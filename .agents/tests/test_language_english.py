import re
from pathlib import Path

# Comprehensive regex for Vietnamese accented characters using unicode escape sequences:
# Latin-1 Supplement: \u00C0-\u00FF
# Latin Extended-A: \u0102-\u01B0
# Latin Extended Additional: \u1EA0-\u1EF9
VIETNAMESE_REGEX = re.compile(
    r"[\u00C0-\u00C3\u00C8-\u00CA\u00CC\u00CD\u00D2-\u00D5\u00D9\u00DA\u00DD"
    r"\u00E0-\u00E3\u00E8-\u00EA\u00EC\u00ED\u00F2-\u00F5\u00F9\u00FA\u00FD"
    r"\u0102\u0103\u0110\u0111\u0168\u0169\u01A0\u01A1\u01AF\u01B0\u1EA0-\u1EF9]"
)

def test_markdown_documentation_is_100_percent_english(markdown_files: list[Path]):
    """Ensure all markdown files contain 0 Vietnamese characters."""
    violations = []
    assert len(markdown_files) > 0, "No markdown files found to scan!"
    for md_file in markdown_files:
        with open(md_file, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                matches = VIETNAMESE_REGEX.findall(line)
                if matches:
                    unique_matches = "".join(set(matches))
                    snippet = line.strip()[:80]
                    violations.append(
                        f"{md_file.name}:{line_no} [{unique_matches}]: {snippet}"
                    )
    assert not violations, (
        f"Found {len(violations)} lines containing Vietnamese text in markdown docs:\n"
        + "\n".join(violations[:20])
    )

def test_all_repository_files_are_100_percent_english(all_repo_files: list[Path]):
    """Ensure all repository source code, scripts, configs, and docs contain 0 Vietnamese characters."""
    violations = []
    assert len(all_repo_files) > 0, "No repository files found to scan!"
    for fpath in all_repo_files:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                matches = VIETNAMESE_REGEX.findall(line)
                if matches:
                    unique_matches = "".join(set(matches))
                    snippet = line.strip()[:80]
                    violations.append(
                        f"{fpath.name}:{line_no} [{unique_matches}]: {snippet}"
                    )
    assert not violations, (
        f"Found {len(violations)} lines containing Vietnamese text across repository files:\n"
        + "\n".join(violations[:20])
    )
