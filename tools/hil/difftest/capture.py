"""Capture tool: send APDUs to a reader and record all traffic as structured JSON.

Usage:
    python3 capture.py --reader "ACR1252" --output golden_acr1252.json
    python3 capture.py --reader "GemPCTwin" --output test_ccid.json
    python3 capture.py --reader "ACR1252" --output session.json --no-fuzz

Records for each test:
    - APDU sent (hex)
    - Response bytes (hex)
    - Status word (SW1 SW2)
    - Duration in milliseconds
    - Success/failure
    - Reader name
    - Card UID
    - Timestamp

Card safety: all APDUs are read-only or expected-to-fail. No mutations.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add parent for apdu_matrix import
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apdu_matrix import ApduTest, get_all_tests


def bytes_to_hex(data: bytes | None) -> str:
    if data is None:
        return ""
    return " ".join(f"{b:02X}" for b in data)


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


def find_reader(pattern: str):
    """Find a reader whose name contains the pattern."""
    from smartcard.System import readers

    available = [str(r) for r in readers()]
    matches = [r for r in available if pattern.lower() in r.lower()]
    if not matches:
        print(f"ERROR: no reader matching '{pattern}' in: {available}", file=sys.stderr)
        sys.exit(1)
    if len(matches) > 1:
        print(f"WARNING: multiple readers match '{pattern}': {matches}", file=sys.stderr)
        print(f"Using first: {matches[0]}", file=sys.stderr)
    # Return the actual reader object
    for r in readers():
        if str(r) == matches[0]:
            return r
    raise RuntimeError(f"Reader object not found for {matches[0]}")


def get_card_uid(conn) -> str:
    """Get card UID via the standard pseudo-APDU."""
    try:
        response, sw1, sw2 = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        if sw1 == 0x90 and sw2 == 0x00:
            return bytes(response).hex().upper()
        return f"uid_error_{sw1:02X}{sw2:02X}"
    except Exception as e:
        return f"uid_exception_{type(e).__name__}"


def send_apdu(conn, apdu_bytes: bytes) -> dict:
    """Send an APDU and record the response."""
    t0 = time.perf_counter()
    try:
        response, sw1, sw2 = conn.transmit(list(apdu_bytes))
        duration_ms = (time.perf_counter() - t0) * 1000
        resp_bytes = bytes(response)
        return {
            "response_hex": bytes_to_hex(resp_bytes),
            "response_bytes": resp_bytes.hex(),
            "sw": f"{sw1:02X}{sw2:02X}",
            "sw1": f"{sw1:02X}",
            "sw2": f"{sw2:02X}",
            "duration_ms": round(duration_ms, 2),
            "success": sw1 == 0x90 and sw2 == 0x00,
            "error": None,
        }
    except Exception as e:
        duration_ms = (time.perf_counter() - t0) * 1000
        return {
            "response_hex": "",
            "response_bytes": "",
            "sw": "",
            "sw1": "",
            "sw2": "",
            "duration_ms": round(duration_ms, 2),
            "success": False,
            "error": f"{type(e).__name__}: {e}",
        }


def run_capture(reader_pattern: str, output_path: str, include_fuzz: bool = True,
                repeat_sleep: float = 0.1) -> dict:
    """Run a full capture session against a reader.

    repeat_sleep: pause between repeats of a repeated test (quick mode trims
    this to 0.02s — safe, the GemPCTwin answers in ~11ms).
    """
    reader = find_reader(reader_pattern)
    reader_name = str(reader)

    print(f"Connecting to: {reader_name}")
    conn = reader.createConnection()
    conn.connect()

    # Get ATR (pyscard returns a list of ints)
    atr = bytes(conn.getATR())
    atr_hex = bytes_to_hex(atr)

    # Get UID
    uid = get_card_uid(conn)
    print(f"ATR: {atr_hex}")
    print(f"UID: {uid}")

    # Get all tests
    tests = get_all_tests(include_fuzz=include_fuzz)
    print(f"Running {len(tests)} tests...")

    results = []
    completed_ids = set()

    for i, test in enumerate(tests):
        result = {
            "test_id": test.test_id,
            "category": test.category,
            "description": test.description,
            "apdu_hex": test.apdu_hex or "",
            "ts": datetime.now(timezone.utc).isoformat(),
            "repeat_index": 0,
        }

        # Handle special tests
        if test.special == "get_atr":
            result.update({
                "response_bytes": atr.hex(),
                "sw": "9000",
                "sw1": "90",
                "sw2": "00",
                "duration_ms": 0,
                "success": True,
                "error": None,
                "special": "atr_on_connect",
            })
            results.append(result)
            completed_ids.add(test.test_id)
            print(f"  [{i+1}/{len(tests)}] {test.test_id}: ATR={atr_hex[:30]}...")
            continue

        if test.special == "get_uid":
            r = send_apdu(conn, bytes([0xFF, 0xCA, 0x00, 0x00, 0x00]))
            result.update(r)
            result["card_uid"] = uid
            results.append(result)
            completed_ids.add(test.test_id)
            print(f"  [{i+1}/{len(tests)}] {test.test_id}: uid={uid}")
            continue

        if test.special == "reconnect":
            # Disconnect and reconnect
            conn.disconnect()
            time.sleep(0.5)
            conn = reader.createConnection()
            conn.connect()
            atr2 = bytes(conn.getATR())
            result.update({
                "response_hex": bytes_to_hex(atr2),
                "response_bytes": atr2.hex(),
                "sw": "9000",
                "sw1": "90",
                "sw2": "00",
                "duration_ms": 0,
                "success": True,
                "error": None,
                "special": "reconnect_atr",
                "atr_match": atr2 == atr,
            })
            results.append(result)
            completed_ids.add(test.test_id)
            print(f"  [{i+1}/{len(tests)}] {test.test_id}: match={atr2 == atr}")
            continue

        # Check prerequisites
        prereqs_met = all(p in completed_ids for p in test.prerequisites)
        if not prereqs_met:
            missing = [p for p in test.prerequisites if p not in completed_ids]
            result.update({
                "response_hex": "",
                "response_bytes": "",
                "sw": "",
                "duration_ms": 0,
                "success": False,
                "error": f"prerequisites_not_met: {missing}",
            })
            results.append(result)
            print(f"  [{i+1}/{len(tests)}] {test.test_id}: SKIP (missing prereqs: {missing})")
            continue

        # Send the APDU (possibly multiple times for repeat tests)
        apdu_bytes = hex_to_bytes(test.apdu_hex)
        for rep in range(test.repeat):
            r = send_apdu(conn, apdu_bytes)
            rep_result = dict(result)
            rep_result.update(r)
            rep_result["repeat_index"] = rep
            if rep > 0:
                rep_result["test_id"] = f"{test.test_id}_r{rep}"
            results.append(rep_result)

            status = "OK" if r["success"] else f"SW={r['sw']}" if r["sw"] else f"ERR={r['error']}"
            if rep == 0:
                print(f"  [{i+1}/{len(tests)}] {test.test_id}: {status} ({r['duration_ms']:.1f}ms)")
            else:
                print(f"    repeat {rep}: {status} ({r['duration_ms']:.1f}ms)")

            # Small pause between repeats
            if rep < test.repeat - 1:
                time.sleep(repeat_sleep)

        completed_ids.add(test.test_id)

    # Disconnect
    try:
        conn.disconnect()
    except Exception:
        pass

    # Build the session document
    session = {
        "reader": reader_name,
        "card_uid": uid,
        "card_atr": atr_hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(tests),
        "total_results": len(results),
        "include_fuzz": include_fuzz,
        "results": results,
    }

    # Save
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(session, indent=2))

    # Summary
    successes = sum(1 for r in results if r.get("success"))
    failures = sum(1 for r in results if not r.get("success") and not (r.get("error") or "").startswith("prerequisites"))
    errors = sum(1 for r in results if r.get("error") and not (r.get("error") or "").startswith("prerequisites"))
    print(f"\nCapture complete: {len(results)} results ({successes} OK, {failures} SW-fail, {errors} errors)")
    print(f"Saved: {output}")

    return session


def main(argv=None):
    parser = argparse.ArgumentParser(description="Capture APDU responses from a reader")
    parser.add_argument("--reader", required=True, help="Reader name pattern (e.g., 'ACR1252', 'GemPCTwin')")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--no-fuzz", action="store_true", help="Skip fuzz cases")
    parser.add_argument("--repeat-sleep", type=float, default=0.1,
                        help="Seconds between repeats of a repeated test (default 0.1)")
    args = parser.parse_args(argv)

    run_capture(args.reader, args.output, include_fuzz=not args.no_fuzz,
                repeat_sleep=args.repeat_sleep)


if __name__ == "__main__":
    main()
