"""Tests for analyzer sanity checks."""

from pathlib import Path

import pytest

from analyzer.checks import CheckError, run_all
from analyzer.cmp import CmpAnalysis
from analyzer.tls import TlsAnalysis


def test_run_all_missing_ca(tmp_path: Path):
    with pytest.raises(CheckError):
        run_all(
            CmpAnalysis(packet_count=0),
            TlsAnalysis(
                version="1.2",
                packet_count=0,
                duration_ms=0,
                client_addr="",
                server_addr="",
                negotiated_cipher="",
                key_share_group="",
                sigalg="",
            ),
            TlsAnalysis(
                version="1.3",
                packet_count=0,
                duration_ms=0,
                client_addr="",
                server_addr="",
                negotiated_cipher="",
                key_share_group="",
                sigalg="",
            ),
            tmp_path,
        )
