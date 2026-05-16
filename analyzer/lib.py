"""Shared analyzer utilities."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def template_env() -> Environment:
    tpl_dir = Path(__file__).parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(tpl_dir)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def write_report(out_dir: Path, name: str, content: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    path.write_text(content, encoding="utf-8")
    return path
