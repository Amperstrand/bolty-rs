# Overnight CCID Boltcard Audit

This directory contains the overnight continuous audit framework for
the bolty-rs CCID reader implementation.

## Re-arming the test

1. Ensure the overnight.env is populated with REST_TOKEN and UIDs
2. Run the overnight suite: python3 tools/hil/overnight/ledger.py
3. Results are written to the results/ directory

See .omo/plans/overnight-ccid-bolty-audit.md for the full plan.