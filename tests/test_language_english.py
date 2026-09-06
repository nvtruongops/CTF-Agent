import re
from pathlib import Path

# Comprehensive regex for Vietnamese accented characters
VIETNAMESE_REGEX = re.compile(
    r'[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ'
    r'ÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ]'
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
