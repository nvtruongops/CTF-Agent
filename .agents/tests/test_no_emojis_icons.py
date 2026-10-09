from pathlib import Path

def is_decorative_emoji(char: str) -> bool:
    cp = ord(char)
    # Emoji & Pictograph ranges:
    # 0x1F300-0x1F5FF: Misc symbols and pictographs
    # 0x1F600-0x1F64F: Emoticons
    # 0x1F680-0x1F6FF: Transport and map symbols
    # 0x1F900-0x1F9FF: Supplemental symbols and pictographs
    # 0x1FA70-0x1FAFF: Symbols and pictographs extended-A
    # 0x2600-0x26FF: Misc symbols (warning signs, pointing hands, etc.)
    # 0x2700-0x27BF: Dingbats
    if 0x1F300 <= cp <= 0x1F64F or 0x1F680 <= cp <= 0x1F6FF or 0x1F900 <= cp <= 0x1FAFF:
        return True
    if 0x2600 <= cp <= 0x27BF:
        return True
    return False

def test_zero_decorative_emojis_across_repo(all_repo_files: list[Path]):
    """Ensure zero decorative emojis exist across all repository documentation and code files."""
    violations = []
    
    assert len(all_repo_files) > 0, "No repository files found to scan!"
    
    for file_path in all_repo_files:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                for char in line:
                    if is_decorative_emoji(char):
                        violations.append(
                            f"{file_path.name}:{line_no} character '{char}' (U+{ord(char):04X})"
                        )
                        break
                        
    assert not violations, (
        f"Found {len(violations)} decorative emojis across repository files:\n"
        + "\n".join(violations[:20])
    )
