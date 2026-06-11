"""NFR-4: no secrets in tracked source (IMPLEMENTATION_PLAN.md M7).

A CI guard that the production source never ships a real credential. Scans every
git-TRACKED file (so the gitignored .env / infra/generated / agent_identity_*.json with
real secrets are out of scope by construction) for high-confidence secret formats. The
tests/ tree is excluded: it deliberately contains FAKE secret-shaped strings to exercise
the output-DLP detector (test_governance) and the discovery/identity fixtures.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# High-confidence real-credential formats — chosen so they do NOT match ordinary code.
_PATTERNS = [
    (re.compile(r"nvapi-[A-Za-z0-9_-]{16,}"), "NVIDIA API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub PAT"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
]

_EXCLUDE_PREFIXES = ("agt-federated-rag/tests/",)
_EXCLUDE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".lock")


def _tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    return [ROOT / line for line in out.stdout.splitlines() if line.strip()]


def test_no_real_secrets_in_tracked_source():
    findings: list[str] = []
    for path in _tracked_files():
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(_EXCLUDE_PREFIXES) or path.suffix.lower() in _EXCLUDE_SUFFIXES:
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for rx, label in _PATTERNS:
            for m in rx.finditer(text):
                token = m.group(0).lower()
                # Skip obvious placeholders / docs-about-secrets (a REAL key never contains
                # these). This is why scanning the audit doc that *discusses* nvapi- keys
                # (with nvapi-XXXX placeholders) is not flagged.
                if any(ph in token for ph in (
                        "xxx", "redact", "placeholder", "example", "change",
                        "your-", "nim-key", "dummy", "fake", "<", "...")):
                    continue
                findings.append(f"{rel}: {label} ({m.group(0)[:10]}…)")
    assert not findings, "real secret(s) detected in tracked source:\n  " + "\n  ".join(findings)


def test_secret_bearing_artifacts_are_gitignored():
    # The files that legitimately hold real secrets must never be tracked.
    tracked = {p.relative_to(ROOT).as_posix() for p in _tracked_files()}
    for rel in tracked:
        assert not rel.endswith(".env"), f"{rel} (a .env) is tracked — secrets must be gitignored"
        assert "infra/generated/" not in rel, f"{rel} under infra/generated is tracked"
        assert not re.search(r"agent_identity.*\.json$", rel), f"{rel} (DID private key) is tracked"
