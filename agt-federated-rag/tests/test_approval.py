"""Approval-workflow regression guards (IMPLEMENTATION_PLAN.md governance).

The Temporal approval activities (grant_access_in_openfga / revoke_pending_in_openfga)
run in the WORKER process and must use an INITIALISED OpenFGA client. A prior bug had
`_get_openfga()` return a bare `OpenFGAAuth()` whose async `_init()` never ran, so
`_write_tuple`'s `assert self._client is not None` failed on every grant — an APPROVED
user was silently never granted access (Temporal retried the activity forever). These
hermetic guards pin the contract: the helper is async and delegates to the shared,
initialised singleton.
"""
from __future__ import annotations

import asyncio
import inspect


def test_get_openfga_is_async():
    # Must be a coroutine function: opening the SDK client requires awaiting _init().
    # A sync helper cannot initialise the client -> the original silent-deny bug.
    from workflow import activities
    assert inspect.iscoroutinefunction(activities._get_openfga)


def test_get_openfga_delegates_to_initialised_singleton(monkeypatch):
    from auth import openfga
    from workflow import activities

    sentinel = object()

    async def fake_get_instance():
        return sentinel

    # get_instance() is the ONLY path that runs _init() (opens the client). Delegating
    # to it — not constructing OpenFGAAuth() directly — is what fixes the bug.
    monkeypatch.setattr(openfga.OpenFGAAuth, "get_instance",
                        classmethod(lambda cls: fake_get_instance()))
    got = asyncio.run(activities._get_openfga())
    assert got is sentinel
