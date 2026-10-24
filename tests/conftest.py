import os

import pytest


@pytest.fixture(autouse=True)
def _no_inherited_issuance_policy(monkeypatch):
    # spawn_broker forwards the caller's CAGE_* settings, so a policy exported in the
    # developer's shell would change what the real-broker tests start. Tests that
    # need a policy set it themselves.
    for name in list(os.environ):
        if name.upper().startswith("CAGE_ISSUANCE_"):
            monkeypatch.delenv(name)
