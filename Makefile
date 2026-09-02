# Bolty-rs test entry points.
#
#   make test           — host unit tests (no hardware; CI parity)
#   make test-hil       — preflight + burn→lock→tap→gated-wipe→blank cycle
#                         (needs ACR1252 + its registered card; mutates the
#                         card but leaves it blank; registry-guarded)
#   make difftest       — 66/66 APDU differential (switches stick role;
#                         auto-restores; needs both readers)
#   make test-all       — everything above in order
#
# Card safety: tools/hil/hil/cards.toml is the contract. Only listed UIDs
# with the matching op are touched; every mutation passes --confirm-uid.

.PHONY: test test-hil difftest test-all

HIL_TESTS := tools/hil/tests

test:
	cargo test --workspace --exclude bolty-esp32
	cargo fmt --check

test-hil:
	python3 -m pytest $(HIL_TESTS) -m "hardware and not role_switch" -v \
	  --json-report --json-report-file=tools/hil/results/hil-test-report.json || \
	  (mkdir -p tools/hil/results && python3 -m pytest $(HIL_TESTS) -m "hardware and not role_switch" -v --json-report --json-report-file=tools/hil/results/hil-test-report.json)

# Takes 10-20 min (role switch + full APDU matrix + capture from both readers + restore).
difftest:
	python3 -m pytest $(HIL_TESTS)/test_difftest.py -v --timeout=1800

test-all: test test-hil difftest
	@echo "=== ALL SUITES PASSED ==="
