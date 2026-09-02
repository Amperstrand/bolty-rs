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
	@echo ""
	@echo "╔════════════════════════════════════════╗"
	@echo "║        ALL SUITES PASSED                ║"
	@echo "╚════════════════════════════════════════╝"
	@echo ""
	@echo "  Host tests:   cargo test --workspace"
	@echo "  HIL cycle:    preflight + burn→lock→tap→gated-wipe→blank"
	@echo "  Difftest:     66/66 APDU differential vs golden"
	@echo ""
	@echo "  Card state:   blank (lab stock, ready for next run)"
	@echo "  Stick role:   bolty (console daemon active)"
	@echo ""

.PHONY: status
status:
	@echo "=== HIL Rig Status ==="
	@timeout 8 python3 tools/hil/bolty-ctl.py PING 2>&1 | head -1 || echo "console: UNREACHABLE"
	@python3 -c "from smartcard.System import readers; [print(f'  reader: {r}') for r in readers()]" 2>/dev/null || echo "  pcscd: no readers"
	@./target/debug/bolty-cli uid 2>&1 | head -2 || echo "  card: not coupled"
	@echo "  labgrid: $(shell systemctl is-active labgrid-exporter 2>/dev/null || echo 'not-running')"
	@echo "  console: $(shell systemctl is-active bolty-console 2>/dev/null || echo 'not-running')"
