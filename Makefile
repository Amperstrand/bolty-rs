# Bolty-rs test entry points.
#
#   make test           — host unit tests (no hardware; CI parity)
#   make test-hil       — preflight + bolty-acr APDU coverage + gated burn/wipe
#                         (ACR only; no role switch; ~5s; card ends blank)
#   make difftest       — 66/66 APDU differential (switches stick role;
#                         auto-restores; 3-4 min; needs both readers)
#   make difftest-quick — gem capture + diff only (no fuzz category, cached
#                         ACR golden; ~60-90s)
#   make test-all       — everything above in order
#   make status         — one-glance rig health
#
# Card safety: tools/hil/hil/cards.toml is the contract. Only listed UIDs
# with the matching op are touched; every mutation passes --confirm-uid.
# Rig exclusivity: session-scoped flock (results/.rig-lock) prevents
# parallel agents from stomping the rig.
# Flaky handling: pytest-rerunfailures with @pytest.mark.flaky(reruns=2)
# on coupling-sensitive tests (ESP-IDF precedent); mutation tests use
# ensure_blank() for rerun-safety.
# History: every run appends to results/history.jsonl.

.PHONY: test test-hil test-hil-lg difftest difftest-quick test-all status report labgrid-place

HIL_TESTS := tools/hil/tests
ALLURE_RESULTS := tools/hil/results/allure

test:
	cargo test --workspace --exclude bolty-esp32
	cargo fmt --check

test-hil:
	mkdir -p tools/hil/results
	python3 -m pytest $(HIL_TESTS) -m "hardware and not role_switch" -v \
	  --reruns 2 --reruns-delay 3 \
	  --json-report --json-report-file=tools/hil/results/hil-test-report.json \
	  --alluredir=$(ALLURE_RESULTS)/$$(date +%Y%m%d-%H%M%S)

# Allure dashboard: history-preserving HTML from the latest test-hil results.
report:
	bash tools/hil/report.sh

# Full labgrid plugin path: place acquisition + env/target fixtures (#79).
# Auto-skips the labgrid test without coordinator reachability issues only
# via rig_lock's flock fallback — this target requires the coordinator up.
test-hil-lg:
	mkdir -p tools/hil/results
	python3 -m pytest $(HIL_TESTS) -m "hardware and not role_switch" -v \
	  --reruns 2 --reruns-delay 3 \
	  --json-report --json-report-file=tools/hil/results/hil-test-report.json \
	  --alluredir=$(ALLURE_RESULTS)/$$(date +%Y%m%d-%H%M%S) \
	  --lg-env=tools/hil/labgrid-env.yaml \
	  --lg-coordinator=192.168.13.221:20408

# Idempotent bolty-rig place (re)creation — run after coordinator restarts.
labgrid-place:
	bash tools/hil/labgrid-place.sh

# Takes 3-4 min (role switch + full APDU matrix + restore).
difftest:
	python3 -m pytest $(HIL_TESTS)/test_difftest.py -v --timeout=1800 \
	  --reruns 1 --reruns-delay 5

# Quick differential: gem capture + diff only (skip fuzz category, skip
# ACR golden re-capture — the golden is committed; ACR re-capture is a
# sanity check, not a test of the thing under test).
difftest-quick:
	cd tools/hil/difftest && python3 e2e.py --phase apdu --quick

test-all: test test-hil difftest
	@echo ""
	@echo "╔════════════════════════════════════════╗"
	@echo "║        ALL SUITES PASSED                ║"
	@echo "╚════════════════════════════════════════╝"
	@echo ""
	@echo "  Host tests:   cargo test --workspace"
	@echo "  HIL cycle:    preflight + ACR APDU + burn→lock→tap→gated-wipe→blank"
	@echo "  Difftest:     66/66 APDU differential vs golden"
	@echo ""
	@echo "  Card state:   blank (lab stock, ready for next run)"
	@echo "  Stick role:   bolty (console daemon active)"
	@echo "  Rig lock:     released"
	@echo "  History:      tools/hil/results/history.jsonl"
	@echo ""

status:
	@echo "=== HIL Rig Status ==="
	@timeout 8 python3 tools/hil/bolty-ctl.py PING 2>&1 | head -1 || echo "console: UNREACHABLE"
	@python3 -c "from smartcard.System import readers; [print(f'  reader: {r}') for r in readers()]" 2>/dev/null || echo "  pcscd: no readers"
	@./target/debug/bolty-cli uid 2>&1 | head -2 || echo "  card: not coupled"
	@echo "  labgrid: $(shell systemctl is-active labgrid-exporter 2>/dev/null || echo 'not-running')"
	@echo "  console: $(shell systemctl is-active bolty-console 2>/dev/null || echo 'not-running')"
	@echo "  lock: $(shell test -f tools/hil/results/.rig-lock && echo 'file exists' || echo 'none')"
	@if test -f tools/hil/results/history.jsonl; then \
	  echo "  last run: $$(tail -1 tools/hil/results/history.jsonl | python3 -c 'import json,sys; d=json.load(sys.stdin); print(f\"{d[\"ts\"]} exit={d[\"exit\"]} {d[\"passed\"]}p/{d[\"failed\"]}f/{d[\"skipped\"]}s\")' 2>/dev/null)"; \
	fi
