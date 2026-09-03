"""--lg-env path: coordinator-mediated rig resources (#79).

These tests exercise the official labgrid pytest plugin (env/target
fixtures) against the live coordinator. They auto-skip without
--lg-env (plugin behavior) — run via `make test-hil-lg`.
"""

import pytest

pytest.importorskip("labgrid")

from labgrid.resource.remote import RemotePlace  # noqa: E402

pytestmark = [pytest.mark.hardware]


def test_rig_place_expands_serial_and_reader(rig_lock, target):
    """The bolty-rig place expands to the exporter's resources: the M5Stick
    serial (NetworkSerialPort) and the ACR1252 acquisition token
    (NetworkSmartcardReader, #78). Depends on rig_lock — the plugin requires
    the place acquired before expansion."""
    assert rig_lock == "labgrid-place"
    place = target.get_resource(RemotePlace)
    assert place.name == "bolty-rig"
    classes = {type(r).__name__ for r in target.resources}
    assert "NetworkSerialPort" in classes, (
        f"M5Stick serial missing from place expansion: {classes}"
    )
    assert "NetworkSmartcardReader" in classes, (
        f"ACR1252 token missing from place expansion: {classes}"
    )
