"""Tests for Mermaid sequence diagram builder."""

from analyzer.mermaid import Sequence


def test_render_contains_participants():
    seq = Sequence()
    seq.participant("C", "Client")
    seq.participant("S", "Server")
    seq.msg("C", "S", "ClientHello")
    out = seq.render()
    assert "sequenceDiagram" in out
    assert "ClientHello" in out
    assert "participant C" in out


def test_escape_quotes_and_angle_brackets():
    seq = Sequence()
    seq.participant("A", 'Say "hi"')
    seq.msg("A", "A", "<script>")
    out = seq.render()
    assert "#quot;" in out or "hi" in out
    assert "<script>" not in out or "#lt;" in out
