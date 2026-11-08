"""audit_log parser tolerance (#256): prose pollution + glued entries.

Fixture lines are verbatim from the 2026-10-19 shared-log evidence
(handoffs/evidence/h1-acr-20261019/) — the reader-table/labgrid-dump
pollution block and a real glued parallel-test line.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hil.audit_log import entries_matching, iter_entries, stats  # noqa: E402

POLLUTED = """reader: ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 03 00
protocol: T=2
UID: 113522BA  SW=9000
EMPTY    atr=-                                        GemPC Twin m5stick MFRC522 00 00
PRESENT  atr=3B888001000000008081710079               ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 03 00
released place ref-acr1252
User    Host             Place             Changed
root    ai-legion        android-emulator  2026-10-19 13:25:25.234603
Reservation '5ITAV357WQ':
  owner: ai-legion/bolty-bench-acr-phase1
  token: 5ITAV357WQ
[1792412328802] EVENT  burn: starting — UID=041065fa967380, version=1, url=https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac} [provenance=DerivedIssuer(1)][1792412328802] EVENT  burn: starting — UID=041065fa967380, version=1, url=https://card.bolt.local/lnurl?p={picc:ctr}&c={mac} [provenance=DerivedIssuer(1)]
[1792412328803] EVENT  burn: SUCCESS — K1-K4 + K0 installed (DerivedIssuer(1)) [provenance=DerivedIssuer(1)]
[1792415197050] GET_UID
[1792415197050] GET_UID OK   uid=04C474FA967380
"""


def _write(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(POLLUTED)
    return p


def test_prose_pollution_yields_no_entries(tmp_path):
    p = _write(tmp_path)
    texts = [t for _, t in iter_entries(p)]
    assert all("GemPC" not in t for t in texts)
    assert all("Reservation" not in t for t in texts)
    assert all("android-emulator" not in t for t in texts)


def test_glued_line_splits_into_two_entries(tmp_path):
    p = _write(tmp_path)
    burns = entries_matching(p, "burn: starting")
    assert len(burns) == 2, f"glued parallel burst must parse as 2 entries: {burns}"
    assert burns[0][0] == burns[1][0] == 1792412328802
    # the two glued variants differ in the URL template
    assert "{picc:uid+ctr}" in burns[0][1]
    assert "{picc:ctr}" in burns[1][1]


def test_entries_in_order_and_counted(tmp_path):
    p = _write(tmp_path)
    all_entries = list(iter_entries(p))
    assert [ts for ts, _ in all_entries] == [
        1792412328802,
        1792412328802,
        1792412328803,
        1792415197050,
        1792415197050,
    ]
    s = stats(p)
    assert s["entries"] == 5
    assert s["prose_lines"] == 11  # reader table + labgrid dump block


def test_clean_log_parses_unchanged(tmp_path):
    p = tmp_path / "clean.log"
    p.write_text(
        "[1793455528345] GET_UID\n"
        "[1793455528345] GET_UID OK   uid=04C474FA967380\n"
    )
    assert stats(p) == {"entries": 2, "prose_lines": 0}
    assert entries_matching(p, "04c474fa967380")
