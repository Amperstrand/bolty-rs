"""B32/B33 ACR1252 check-in probe (docs/lessons-learned.md B32, B33).

One no-auth PC/SC exchange — connect + status on the PICC slot — proving
the CCID bulk pipe is alive, plus a B33 NVM config audit. Reader states:

    ok       reader answered (ATR captured) AND auto-polling enabled
    cfg      reader answers fine but auto-polling is disabled in EEPROM
             (B33: the "dead reader" that was never dead — restore is
             two writes, no replug; heal via `--restore`)
    absent   reader healthy, no card coupled (connect = NoSmartcard — the
             reader ANSWERED, which is the opposite of a wedge); the B33
             config audit still runs so a poll-off reader cannot
             masquerade as "no card placed" (#208 sweep confusion)
    wedge    pcscd lists the reader but the bulk pipe does not complete
             (the B32 signature: control endpoint alive, CCID hung)
    absent   no ACR1252 PICC reader in the pcscd reader list
    no-service pcscd itself unreachable
    unknown  pyscard not installed (host CI) — probe cannot run

Owner decision 2026-10-19: no switched-power hub on this bench, so the
deep-wedge class stays owner-replug-only; prevention + early detection
are load-bearing (this probe is the early-detection half).

B33 config facts (ACR1252U API V1.17 §5.7.3/§5.7.4/§5.4.7/§5.4.8):
  FF 00 50 00 00      get PICC operating param  -> "90 <param>"
                      (bit7 auto-poll, bit6 auto-ATS, bit5 interval 250ms,
                       bit4-0 tag types; NOT a status word — see B33)
  FF 00 51 <p> 00     set PICC operating param  (bench default 0xFF)
  CTL_CODE(1)+E0 00 00 23 00   read automatic polling setting
                               -> "E1 00 00 00 01 <setting>"
  CTL_CODE(1)+E0 00 00 23 01 <s>  set polling (doc default 0x8B; V1.02
                               said 0x8F) — SAVED TO NON-VOLATILE MEMORY
Both registers survive replugs AND host moves. For temporary RF quiet,
use a transparent session (FF C2 ... 81/82, API §5.2.1) instead — it
suspends auto-polling and restores it on session end without touching
EEPROM.

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

# B33: escape routing on this pcscd/ccid stack is SCARD_CTL_CODE(1) =
# 0x42000001; CM_IOCTL_SMARTCARD_DIRECT (CTL_CODE 1960) returns
# SCARD_E_UNKNOWN_READER-MAPPED error 0x8010001f here (verified live).
CTL_ESCAPE = 0x42000001
GET_PICC_PARAM = [0xFF, 0x00, 0x50, 0x00, 0x00]
SET_PICC_PARAM = [0xFF, 0x00, 0x51]  # + <param> + 0x00
READ_POLLING = [0xE0, 0x00, 0x00, 0x23, 0x00]
SET_POLLING = [0xE0, 0x00, 0x00, 0x23, 0x01]  # + <setting>
POLLING_DEFAULT = 0x8B  # doc default (V1.17); V1.02 documented 0x8F
PICC_PARAM_DEFAULT = 0xFF  # poll+ATS on, 250 ms, all tag types


def parse_picc_param(resp) -> "int | None":
    """'90 <param>' -> param byte. B33: 90 3F was misread for two days as
    an 'abnormal firmware response'; it is simply the param echo."""
    if resp and len(resp) == 2 and resp[0] == 0x90:
        return resp[1]
    return None


def parse_polling(resp) -> "int | None":
    """'E1 00 00 00 01 <setting>' -> setting byte."""
    if resp and len(resp) == 6 and resp[0] == 0xE1 and resp[4] == 0x01:
        return resp[5]
    return None


def audit_config(cfg: dict) -> "tuple[bool, str]":
    """True iff auto-polling is enabled in BOTH registers (B33 contract:
    bit7 of the PICC operating param, bit0 of the polling setting)."""
    notes = []
    ok = True
    p = cfg.get("picc_param")
    if p is None:
        notes.append("picc-param unreadable")
        ok = False
    elif not p & 0x80:
        notes.append(f"picc-param {p:#04x} auto-poll OFF")
        ok = False
    else:
        notes.append(f"picc-param {p:#04x}")
    s = cfg.get("polling")
    if s is None:
        notes.append("polling-setting unreadable")
        ok = False
    elif not s & 0x01:
        notes.append(f"polling {s:#04x} auto-poll OFF")
        ok = False
    else:
        notes.append(f"polling {s:#04x}")
    return ok, ", ".join(notes)


def _read_config(ctx, target: str) -> dict:
    """B33 audit read: both NVM registers via a direct-mode handle."""
    from smartcard.scard import (
        SCARD_LEAVE_CARD,
        SCARD_SHARE_DIRECT,
        SCardConnect,
        SCardControl,
        SCardDisconnect,
        SCardTransmit,
    )

    cfg = {"picc_param": None, "polling": None}
    rc, h, _ = SCardConnect(ctx, target, SCARD_SHARE_DIRECT, 0)
    if rc != 0:
        return cfg
    try:
        rc, resp = SCardTransmit(h, 0, GET_PICC_PARAM)
        if rc == 0:
            cfg["picc_param"] = parse_picc_param(bytes(resp))
        rc, resp = SCardControl(h, CTL_ESCAPE, READ_POLLING)
        if rc == 0:
            cfg["polling"] = parse_polling(bytes(resp))
    finally:
        SCardDisconnect(h, SCARD_LEAVE_CARD)
    return cfg


def restore_defaults() -> dict:
    """B33 heal: rewrite both NVM registers to bench defaults and verify.
    No pcscd restart, no replug — direct-mode writes under the already
    held rig lock (this is why cfg-heal is safe to auto-run where the
    B32 shallow heal is opt-in)."""
    try:
        from smartcard.scard import (
            SCARD_LEAVE_CARD,
            SCARD_SCOPE_USER,
            SCARD_SHARE_DIRECT,
            SCardConnect,
            SCardControl,
            SCardDisconnect,
            SCardEstablishContext,
            SCardListReaders,
            SCardReleaseContext,
            SCardTransmit,
        )
        from smartcard.scard import SCardGetErrorMessage
    except ImportError:
        return {"restored": False, "detail": "pyscard not installed"}

    rc, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
    if rc != 0:
        return {"restored": False, "detail": SCardGetErrorMessage(rc)}
    rc, readers = SCardListReaders(ctx, [])
    readers = list(readers or [])
    target = next((r for r in readers if all(n in r for n in PICC_NEEDLES)), None)
    if target is None:
        SCardReleaseContext(ctx)
        return {"restored": False, "detail": "no ACR1252 PICC slot"}

    rc, h, _ = SCardConnect(ctx, target, SCARD_SHARE_DIRECT, 0)
    if rc != 0:
        SCardReleaseContext(ctx)
        return {"restored": False, "detail": SCardGetErrorMessage(rc)}
    try:
        SCardTransmit(h, 0, SET_PICC_PARAM + [PICC_PARAM_DEFAULT, 0x00])
        SCardControl(h, CTL_ESCAPE, SET_POLLING + [POLLING_DEFAULT])
        cfg = _read_config(ctx, target)
    finally:
        SCardDisconnect(h, SCARD_LEAVE_CARD)
        SCardReleaseContext(ctx)
    ok, notes = audit_config(cfg)
    return {"restored": ok, "config": cfg, "detail": notes}


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
                # SCARD_E_NO_SMARTCARD = the reader ANSWERED pcsc with
                # "no card" — healthy reader, empty field; the opposite
                # of a wedge. Match the code (0x8010000C), not the
                # message string (spelling varies by pcsc-lite version).
                state = "absent" if rc == 0x8010000C else "wedge"
                if state == "absent":
                    cfg = _read_config(ctx, target)
                    ok, notes = audit_config(cfg)
                    SCardReleaseContext(ctx)
                    if not ok:
                        return {
                            "state": "cfg",
                            "detail": f"no card coupled AND {notes} — B33 "
                                      "poll-off masquerading as 'no card "
                                      "placed' (#208); restore, no replug",
                        }
                else:
                    SCardReleaseContext(ctx)
                return {"state": state, "detail": SCardGetErrorMessage(rc)}
            rc, _rn, _st, _pr, atr = SCardStatus(h)
            detail = (
                f"ATR {bytes(atr).hex()}"
                if rc == 0
                else f"status: {SCardGetErrorMessage(rc)}"
            )
            state = "ok" if rc == 0 else "wedge"
            SCardDisconnect(h, SCARD_LEAVE_CARD)
            if state == "ok":
                cfg = _read_config(ctx, target)
                ok, notes = audit_config(cfg)
                if not ok:
                    return {
                        "state": "cfg",
                        "detail": f"card coupled but {notes} — B33 config "
                                  "drift; restore before card-mutating work",
                    }
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


def cfg_heal_hint() -> str:
    return (
        "[acr-checkin] B33 config heal: `python3 -m hil.acr_probe --restore` "
        "from tools/hil/ (no pcscd restart, no replug — direct-mode writes "
        "of the documented defaults 0xFF / 0x8B)."
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--restore", action="store_true",
        help="rewrite both B33 NVM registers to defaults, then probe",
    )
    args = parser.parse_args()
    if args.restore:
        result = restore_defaults()
        result = {"state": "cfg-heal", **result}
        print(json.dumps(result))
        if not result["restored"]:
            raise SystemExit(1)
    else:
        result = probe()
        if args.json:
            print(json.dumps(result))
        else:
            print(f"{result['state']}: {result['detail']}")
