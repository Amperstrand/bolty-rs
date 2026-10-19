"""B32 ACR1252 check-in probe (docs/lessons-learned.md B32).

One no-auth PC/SC exchange — connect + status on the PICC slot — proving
the CCID bulk pipe is alive. Reader state classes:

    ok       reader answered (ATR captured)
    wedge    pcscd lists the reader but the bulk pipe does not complete
             (the B32 signature: control endpoint alive, CCID hung)
    absent   no ACR1252 PICC reader in the pcscd reader list
    no-service pcscd itself unreachable
    unknown  pyscard not installed (host CI) — probe cannot run

Owner decision 2026-10-19: no switched-power hub on this bench, so the
deep-wedge class stays owner-replug-only; prevention + early detection
are load-bearing (this probe is the early-detection half).

The probe runs ISOLATED by default: a wedged reader can hang USB I/O
indefinitely, so probe_isolated() spawns this module as a short-lived
subprocess with a hard timeout and classifies the timeout itself as the
wedge signature — the one mid-exchange kill that is safe by design.
"""

import json
import subprocess
import sys
from pathlib import Path

HIL_ROOT = Path(__file__).resolve().parent.parent

PICC_NEEDLES = ("ACR1252", "PICC")

PROBE_TIMEOUT_S = 25.0


def probe() -> dict:
    """Direct in-process probe (see module docstring for states)."""
    try:
        from smartcard.scard import (
            SCARD_LEAVE_CARD,
            SCARD_PROTOCOL_T0,
            SCARD_PROTOCOL_T1,
            SCARD_SCOPE_USER,
            SCARD_SHARE_SHARED,
            SCardConnect,
            SCardDisconnect,
            SCardEstablishContext,
            SCardListReaders,
            SCardReleaseContext,
            SCardStatus,
        )
        from smartcard.scard import SCardGetErrorMessage
        from smartcard.Exceptions import SmartcardException
    except ImportError:
        return {"state": "unknown", "detail": "pyscard not installed"}

    try:
        rc, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
        if rc != 0:
            return {"state": "no-service", "detail": SCardGetErrorMessage(rc)}
        rc, readers = SCardListReaders(ctx, [])
        if rc != 0:
            SCardReleaseContext(ctx)
            return {"state": "no-service", "detail": SCardGetErrorMessage(rc)}
        readers = list(readers or [])
        target = next(
            (r for r in readers if all(n in r for n in PICC_NEEDLES)), None
        )
        if target is None:
            SCardReleaseContext(ctx)
            return {
                "state": "absent",
                "detail": f"no ACR1252 PICC slot among {len(readers)} readers",
            }
        try:
            rc, h, _proto = SCardConnect(
                ctx, target, SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            )
            if rc != 0:
                SCardReleaseContext(ctx)
                return {"state": "wedge", "detail": SCardGetErrorMessage(rc)}
            rc, _rn, _st, _pr, atr = SCardStatus(h)
            detail = (
                f"ATR {bytes(atr).hex()}"
                if rc == 0
                else f"status: {SCardGetErrorMessage(rc)}"
            )
            state = "ok" if rc == 0 else "wedge"
            SCardDisconnect(h, SCARD_LEAVE_CARD)
            SCardReleaseContext(ctx)
            return {"state": state, "detail": detail}
        except SmartcardException as exc:
            SCardReleaseContext(ctx)
            return {"state": "wedge", "detail": str(exc)}
    except Exception as exc:  # never raise out of a probe
        return {"state": "unknown", "detail": repr(exc)}


def probe_isolated(timeout_s: float = PROBE_TIMEOUT_S) -> dict:
    """Run probe() in a killable subprocess. A hard timeout IS the wedge
    signature (bulk pipe not completing) — classified, not raised."""
    try:
        r = subprocess.run(
            [sys.executable, "-m", "hil.acr_probe", "--json"],
            capture_output=True, text=True, timeout=timeout_s,
            cwd=str(HIL_ROOT),
        )
    except subprocess.TimeoutExpired:
        return {
            "state": "wedge",
            "detail": f"probe did not complete in {timeout_s}s "
                      "(CCID bulk pipe hung — B32 signature)",
        }
    except OSError as exc:
        return {"state": "unknown", "detail": f"probe spawn failed: {exc}"}
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return {"state": "unknown", "detail": (r.stderr or r.stdout or "")[:200]}


def heal_hint() -> str:
    return (
        "[acr-checkin] B32 shallow heal: end sessions holding the reader, "
        "`systemctl restart pcscd`, re-run. If the probe still fails after "
        "USBDEVFS_RESET / authorized toggle (B32 ladder), it is the deep "
        "class — owner replug; do not loop software heals (B29 rule 3)."
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = probe()
    if args.json:
        print(json.dumps(result))
    else:
        print(f"{result['state']}: {result['detail']}")
