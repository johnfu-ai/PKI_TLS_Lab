"""Build Mermaid sequenceDiagram blocks from structured events."""

from __future__ import annotations

import re


def _escape(text: str) -> str:
    """Escape characters that break Mermaid labels."""
    text = text.replace("\\", "\\\\")
    text = text.replace('"', "#quot;")
    text = text.replace("<", "#lt;")
    text = text.replace(">", "#gt;")
    text = re.sub(r"[\r\n]+", "<br/>", text)
    return text


class Sequence:
    def __init__(self) -> None:
        self._participants: list[tuple[str, str]] = []
        self._messages: list[tuple[str, str, str, str | None]] = []
        self._notes: list[tuple[str, str, str]] = []

    def participant(self, alias: str, label: str | None = None) -> Sequence:
        self._participants.append((alias, label or alias))
        return self

    def msg(
        self,
        src: str,
        dst: str,
        label: str,
        *,
        note: str | None = None,
    ) -> Sequence:
        self._messages.append((src, dst, label, note))
        return self

    def note(self, over: str, text: str) -> Sequence:
        """Add a Note over participants (comma-separated aliases)."""
        self._notes.append((over, text, ""))
        return self

    def render(self) -> str:
        lines = ["```mermaid", "sequenceDiagram", "    autonumber"]
        seen: set[str] = set()
        for alias, label in self._participants:
            if alias not in seen:
                lines.append(f'    participant {alias} as "{_escape(label)}"')
                seen.add(alias)
        for over, text, _ in self._notes:
            lines.append(f'    Note over {over}: {_escape(text)}')
        for src, dst, label, note in self._messages:
            lines.append(f'    {src}->>{dst}: {_escape(label)}')
            if note:
                side = "right of" if dst == src else f"right of {dst}"
                lines.append(f'    Note {side} {dst}: {_escape(note)}')
        lines.append("```")
        return "\n".join(lines)
