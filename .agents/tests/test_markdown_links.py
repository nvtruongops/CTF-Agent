import re
from pathlib import Path

def strip_code_blocks(text: str) -> str:
    """Remove fenced and inline code blocks so code syntax like obj[key](arg) is ignored."""
    text = re.sub(r'```[\s\S]*?```', '', text)
    text = re.sub(r'`[^`\n]+`', '', text)
    return text

# Match standard markdown links: [text](target)
LINK_PATTERN = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

def test_markdown_relative_links_resolve(markdown_files: list[Path]):
    """Verify that all internal markdown relative links point to existing files."""
    broken_links = []
    total_links_checked = 0
    
    assert len(markdown_files) > 0
    
    for md_file in markdown_files:
        with open(md_file, "r", encoding="utf-8", errors="ignore") as f:
            content = strip_code_blocks(f.read())
            
        for match in LINK_PATTERN.finditer(content):
            text, target = match.groups()
            target = target.strip()
            
            # Skip external endpoints, mailto, and pure in-page anchors
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            
            # Skip dummy placeholder targets in docs (e.g. target.md inside docs, or example syntax)
            if target in {"target.md", "/path/to/file"} or target.startswith(("$", "<")):
                continue
                
            # Strip anchor fragment from URL
            target_path_str = target.split("#")[0]
            if not target_path_str:
                continue
                
            total_links_checked += 1
            resolved = (md_file.parent / target_path_str).resolve()
            
            if not resolved.exists():
                broken_links.append(f"{md_file.name}: [{text}]({target}) -> not found at {resolved}")
                
    assert not broken_links, (
        f"Found {len(broken_links)} broken relative markdown links out of {total_links_checked} checked:\n"
        + "\n".join(broken_links[:20])
    )
