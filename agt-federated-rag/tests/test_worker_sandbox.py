"""Worker-startup sandbox guard (regression guard).

A @workflow.defn module is re-imported inside Temporal's DETERMINISTIC sandbox when the
worker registers it. If such a module imports a non-deterministic module (structlog ->
random.getrandbits, secrets, urllib, ...) at TOP LEVEL — outside
`with workflow.unsafe.imports_passed_through():` — the sandbox raises
RestrictedWorkflowAccessError and the ENTIRE worker fails to start. That exact bug shipped
once (workflow/rotation.py imported structlog at module top) and 119 unit tests stayed green
because none of them start a worker — only the live e2e caught it.

This static guard parses every workflow/*.py that defines a @workflow.defn and asserts none
import a sandbox-hostile module at module scope. Deterministic, no Temporal server needed.
"""
from __future__ import annotations

import ast
from pathlib import Path

# Modules the Temporal workflow sandbox restricts (IO / non-determinism). Importing any of
# these at a workflow module's TOP LEVEL breaks worker startup; they must be inside
# imports_passed_through() or inside the activity functions.
_HOSTILE = {"structlog", "secrets", "random", "urllib", "requests", "httpx", "socket", "ssl"}

_WORKFLOW_DIR = Path(__file__).resolve().parents[1] / "workflow"


def _defines_workflow(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                # match @workflow.defn (and @workflow.defn(...))
                d = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(d, ast.Attribute) and d.attr == "defn":
                    return True
    return False


def _top_level_hostile_imports(tree: ast.Module) -> list[str]:
    """Hostile modules imported as DIRECT children of the module body (i.e. not inside a
    `with imports_passed_through()` block and not inside a function)."""
    bad: list[str] = []
    for node in tree.body:                      # only module-scope statements
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in _HOSTILE:
                    bad.append(root)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _HOSTILE:
                bad.append(root)
    return bad


def test_no_workflow_module_has_top_level_hostile_imports():
    offenders = {}
    for path in _WORKFLOW_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not _defines_workflow(tree):
            continue
        bad = _top_level_hostile_imports(tree)
        if bad:
            offenders[path.name] = sorted(set(bad))
    assert not offenders, (
        "workflow-defining modules import sandbox-hostile modules at top level (move them "
        "inside `with workflow.unsafe.imports_passed_through():` or into the activity) — "
        "this breaks worker startup:\n  " + "\n  ".join(f"{k}: {v}" for k, v in offenders.items())
    )


def test_guard_actually_detects_a_violation(tmp_path):
    # Prove the guard isn't vacuous: a workflow module importing structlog at top is flagged.
    bad_src = "import structlog\nfrom temporalio import workflow\n@workflow.defn\nclass W:\n    pass\n"
    tree = ast.parse(bad_src)
    assert _defines_workflow(tree)
    assert "structlog" in _top_level_hostile_imports(tree)
    # ...and the same imports under imports_passed_through() are NOT flagged.
    good_src = ("from temporalio import workflow\n"
                "with workflow.unsafe.imports_passed_through():\n    import structlog\n"
                "@workflow.defn\nclass W:\n    pass\n")
    assert _top_level_hostile_imports(ast.parse(good_src)) == []
