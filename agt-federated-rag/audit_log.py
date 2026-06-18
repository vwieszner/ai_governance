"""Tamper-evident, hash-chained audit log (IMPLEMENTATION_PLAN.md M8).

Every governance event the system already emits with ``agt_audit=True`` (authorization
decisions, OpenFGA grant/revoke/pending writes, approval decisions, kill-switch, peer
calls) is appended to an append-only, hash-chained log so that any modification,
deletion, or reordering of past audit entries is *detectable*.

Each entry chains to the previous one. By default the link is a keyless digest:

    hash = SHA256( seq | ts | event | canonical(data) | prev_hash )

so entry N's hash depends on entry N-1's hash (genesis prev_hash = 64 zeros). Recomputing
the chain (see :func:`verify_chain`) detects: a tampered field (hash mismatch), a deleted
or reordered entry (seq gap / prev_hash mismatch), or a truncated tail.

Tamper-EVIDENT → tamper-PROOF (THREAT_MODEL §4.1): the keyless digest is only tamper-
*evident* — an attacker who compromises the agent *host* can recompute a forged chain (and
the local sidecar anchor) because nothing in the link is secret. When an HMAC key IS
configured (``AUDIT_HMAC_KEY`` resolved from the secrets backend — a Vault ref the agent
reads at runtime but a disk-rewriting attacker does NOT hold), the link becomes keyed:

    hash = HMAC-SHA256( key, seq | ts | event | canonical(data) | prev_hash )

so a forged chain — even one re-rooted at genesis and recomputed end-to-end — fails
verification without the key. This is OPT-IN and BACKWARD-COMPATIBLE: with no key the
behaviour is byte-for-byte the keyless chain above (existing chains keep verifying). With a
key, :func:`verify_chain` REQUIRES it and rejects any keyless (forged) chain fail-closed.

Custody caveat (honest): the key must live somewhere the agent process can READ but a
host-compromise attacker cannot — i.e. the secrets backend (Vault). If the key is placed in
the same env/.env file an attacker who owns the host can read, the HMAC adds no assurance
over the keyless chain (it is then "a key the agent can read" — security theatre, per §4.1).
The backend indirection (``vault:`` ref) is what makes this real; remote shipment to an
append-only collector (the existing anchor sink) remains the recommended complement.

Process model: the agent (api.main) and the Temporal worker (workflow.worker) are SEPARATE
processes that both emit ``agt_audit`` events. To avoid a cross-process write race on a
single chain, each writes its OWN per-(division, role) chain file
(``<division>_<role>.jsonl``); verification covers all of a division's chains. Each chain
continues across process restarts (the tail hash/seq are reloaded on startup).

Capture is DRY: :func:`configure_audit_logging` inserts :func:`_audit_processor` into the
structlog pipeline (before the renderer), so existing ``agt_audit=True`` log calls are
recorded automatically — no call-site changes. The processor never raises (a failing audit
write must not break request logging) but records a sentinel error entry if it ever does.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import structlog

GENESIS = "0" * 64

# Settings value whose VALUE is the HMAC key (or a ``vault:`` ref resolved by the secrets
# backend). Empty/unset → keyless chain (backward-compatible). The env name is read directly
# here (audit_log has no settings object); a deployment sets it to a ``vault:`` ref so the key
# is never in an env file — see secrets_backend.resolve_secret.
_HMAC_ENV = "AUDIT_HMAC_KEY"


def _canonical(data: dict) -> str:
    """Deterministic JSON for hashing — sorted keys, no whitespace, str() fallback."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def resolve_audit_hmac_key() -> bytes | None:
    """The configured audit HMAC key as bytes, or None when keyless (the default).

    The raw value comes from ``$AUDIT_HMAC_KEY``; if it's a ``vault:`` ref it is resolved
    through the secrets backend (so the key lives in Vault, not an env file). An empty/unset
    value means no key → keyless chain (backward-compatible). A ref that fails to resolve
    raises (fail loud — a configured-but-unresolvable key must NOT silently fall back to
    keyless, which would be a downgrade)."""
    raw = os.environ.get(_HMAC_ENV, "").strip()
    if not raw:
        return None
    try:
        from secrets_backend import is_ref, resolve_secret
        if is_ref(raw):
            raw = resolve_secret(raw)
    except ImportError:  # secrets_backend unavailable → treat the value as a literal key
        pass
    return raw.encode("utf-8") if raw else None


def _entry_hash(seq: int, ts: str, event: str, data: dict, prev_hash: str,
                key: bytes | None = None) -> str:
    """Chain link. Keyless (SHA256) by default; HMAC-SHA256 when ``key`` is set so a forged
    chain (recomputed without the key) fails verification. Same message preimage either way,
    so a keyless chain and a keyed chain differ ONLY by the key — never by layout."""
    msg = f"{seq}|{ts}|{event}|{_canonical(data)}|{prev_hash}".encode("utf-8")
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


class AuditChain:
    """Append-only, hash-chained audit file for one (division, role).

    External anchoring (M8 review finding): a pure local chain cannot detect tail
    truncation or whole-file deletion — an attacker who owns the file can drop the tail or
    delete it. So each append also publishes the new HEAD (seq, hash) to an append-only
    ANCHOR sink the attacker would have to tamper with consistently: a remote collector
    (``AUDIT_ANCHOR_URL``) when set, else a separate local anchor file. verify_chain then
    cross-checks the chain tail against the highest anchored head — truncation below it, or
    a missing chain with a non-empty anchor, is flagged.
    """

    def __init__(self, path: str | os.PathLike, anchor_path: str | os.PathLike | None = None,
                 anchor_url: str | None = None, hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_path = Path(anchor_path) if anchor_path else self.path.with_suffix(".anchor.jsonl")
        self.anchor_url = anchor_url or os.environ.get("AUDIT_ANCHOR_URL", "")
        # HMAC key: explicit arg wins (tests), else resolved from the secrets backend at
        # construction. None → keyless chain (backward-compatible default).
        self._hmac_key = hmac_key if hmac_key is not None else resolve_audit_hmac_key()
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._load_tail()

    def _load_tail(self) -> tuple[int, str]:
        """Resume the chain across restarts: read the last entry's seq + hash."""
        if not self.path.exists():
            return -1, GENESIS
        last_line = ""
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()
        if not last_line:
            return -1, GENESIS
        rec = json.loads(last_line)
        return int(rec["seq"]), str(rec["hash"])

    def append(self, event: str, data: dict | None = None) -> dict:
        """Append one entry, returning the written record. Thread-safe + durable (fsync)."""
        # Normalise to JSON-native FIRST so the hash computed here matches the hash
        # recomputed from the re-parsed file in verify_chain (no default=str drift).
        norm: dict = json.loads(json.dumps(data or {}, default=str))
        with self._lock:
            seq = self._seq + 1
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            prev = self._last_hash
            h = _entry_hash(seq, ts, event, norm, prev, self._hmac_key)
            rec = {"seq": seq, "ts": ts, "event": event, "data": norm,
                   "prev_hash": prev, "hash": h}
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._seq, self._last_hash = seq, h
            self._anchor_head(seq, h, ts)
            return rec

    def _anchor_head(self, seq: int, h: str, ts: str) -> None:
        """Publish the new head to the anchor sink. Best-effort: an anchor failure must
        never break the audited request path (the local chain is still written)."""
        head = {"seq": seq, "hash": h, "ts": ts}
        try:
            if self.anchor_url:
                import urllib.request
                req = urllib.request.Request(
                    self.anchor_url, data=json.dumps(head).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
                urllib.request.urlopen(req, timeout=5).close()
            else:
                with self.anchor_path.open("a", encoding="utf-8") as af:
                    af.write(json.dumps(head) + "\n")
                    af.flush()
                    os.fsync(af.fileno())
        except Exception:  # noqa: BLE001 — anchoring is best-effort
            pass


def _load_anchor_head(anchor_path: Path) -> dict | None:
    """Highest anchored head {seq, hash} from a local anchor file, or None."""
    if not anchor_path.exists():
        return None
    best: dict | None = None
    with anchor_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if best is None or int(rec.get("seq", -1)) > int(best.get("seq", -1)):
                best = rec
    return best


_RESOLVE_KEY = object()  # sentinel: verify_chain should resolve the key from the backend


def verify_chain(path: str | os.PathLike, anchor_path: str | os.PathLike | None = None,
                 key: bytes | None | object = _RESOLVE_KEY) -> tuple[bool, str]:
    """Verify a chain file end-to-end, cross-checked against its external anchor.

    Returns (ok, detail). Detects, in addition to the in-chain checks (tamper/reorder/
    internal-deletion): tail TRUNCATION and whole-file DELETION, by comparing the chain
    tail against the highest anchored head (the M8 review gap). Without an anchor it falls
    back to chain-only verification (the prior behaviour).

    Key handling (THREAT_MODEL §4.1):
      - ``key`` omitted (default): the HMAC key is resolved from the secrets backend
        (``AUDIT_HMAC_KEY``). When one is configured, verification is KEYED — a keyless
        forged chain (the host-compromise attacker recomputing from genesis) fails. When
        none is configured, verification is keyless (backward-compatible — existing
        callers and chains are unaffected).
      - ``key=b"..."``: verify against that explicit key (tests / out-of-band verifiers).
      - ``key=None``: force keyless verification regardless of the environment.
    """
    p = Path(path)
    ap = Path(anchor_path) if anchor_path else p.with_suffix(".anchor.jsonl")
    anchor = _load_anchor_head(ap)
    hkey: bytes | None = resolve_audit_hmac_key() if key is _RESOLVE_KEY else key  # type: ignore[assignment]

    if not p.exists():
        # A missing chain is only OK if the anchor is also empty/absent.
        if anchor is not None:
            return False, (f"chain file missing but anchor records up to seq {anchor.get('seq')} "
                           f"— whole-file deletion detected")
        return True, "no audit file (empty chain)"

    prev = GENESIS
    expected_seq = 0
    tail_seq = -1
    tail_hash = GENESIS
    with p.open("r", encoding="utf-8") as f:
        for ln_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                return False, f"line {ln_no}: not valid JSON (corrupted)"
            if int(rec.get("seq", -1)) != expected_seq:
                return False, (f"line {ln_no}: seq {rec.get('seq')} != expected "
                               f"{expected_seq} — deletion/reorder/truncation")
            if rec.get("prev_hash") != prev:
                return False, f"seq {rec.get('seq')}: prev_hash mismatch — chain broken"
            recomputed = _entry_hash(rec["seq"], rec["ts"], rec["event"],
                                     rec.get("data", {}), rec["prev_hash"], hkey)
            if not hmac.compare_digest(recomputed, str(rec.get("hash", ""))):
                # When a key is configured this also rejects a forged KEYLESS chain (its
                # SHA256 hashes won't equal the HMAC recompute) — the §4.1 tamper-proofing.
                detail = "hash mismatch — entry tampered"
                if hkey is not None:
                    detail += " (or chain not produced with the configured HMAC key)"
                return False, f"seq {rec.get('seq')}: {detail}"
            prev = rec["hash"]
            tail_seq, tail_hash = int(rec["seq"]), str(rec["hash"])
            expected_seq += 1

    # Anchor cross-check: the chain must reach at least the highest anchored head, and the
    # hash at that seq must match (catches tail truncation + downstream rewrite-below-anchor).
    if anchor is not None:
        a_seq = int(anchor.get("seq", -1))
        if tail_seq < a_seq:
            return False, (f"chain tail seq {tail_seq} < anchored seq {a_seq} "
                           f"— tail truncation detected")
        if tail_seq == a_seq and tail_hash != anchor.get("hash"):
            return False, f"seq {a_seq}: head hash != anchored hash — chain rewritten"
    return True, f"OK — {expected_seq} entries verified" + (
        f" (anchor seq {anchor.get('seq')})" if anchor else "")


# Explicit ALLOWLIST of fields that may enter the immutable chain (M8 review): switch the
# processor from copy-all-minus-2 to copy-only-these, so a future structlog .bind() or a new
# field on any agt_audit call can NEVER land a token / query / answer / PII into the chain.
AUDIT_FIELD_ALLOWLIST = frozenset({
    "user_id", "chunk_id", "relation", "allowed", "decision", "division_id", "flow",
    "count", "pending", "denied", "approval_request_id", "request_id", "task_id",
    "peer_did", "signer_did", "trust_score", "source_division", "action", "reason",
    "did", "hmac", "error", "subject", "count_dropped",
})


# ── structlog integration (DRY capture of agt_audit=True events) ────────────────

_chain: AuditChain | None = None
log = structlog.get_logger(__name__)

# ── Metrics (Phase-1 item 13): dependency-free Prometheus counters ──────────────
# Every agt_audit event increments a per-event counter (and a total). The same DRY hook
# that feeds the audit chain feeds metrics, so no call-site changes. render_prometheus()
# emits text-format for a /metrics scrape; alert rules key on these event names.
_metrics: dict[str, int] = {}
_metrics_lock = threading.Lock()


def _bump_metric(event: str) -> None:
    with _metrics_lock:
        _metrics[event] = _metrics.get(event, 0) + 1


def render_prometheus() -> str:
    """Prometheus text-format snapshot of the audit-event counters."""
    with _metrics_lock:
        items = sorted(_metrics.items())
    lines = [
        "# HELP agt_audit_events_total AGT governance audit events by type.",
        "# TYPE agt_audit_events_total counter",
    ]
    total = 0
    for event, n in items:
        safe = "".join(c if (c.isalnum() or c == "_") else "_" for c in event)
        lines.append(f'agt_audit_events_total{{event="{safe}"}} {n}')
        total += n
    lines.append("# HELP agt_audit_events_sum Total audit events recorded this process.")
    lines.append("# TYPE agt_audit_events_sum counter")
    lines.append(f"agt_audit_events_sum {total}")
    return "\n".join(lines) + "\n"


def _audit_processor(logger: Any, method_name: str, event_dict: dict) -> dict:
    """structlog processor: record agt_audit=True events into the chain. Returns the
    event_dict unchanged so normal rendering continues. Never raises."""
    if event_dict.get("agt_audit"):
        _bump_metric(str(event_dict.get("event", "")))      # metrics even before a chain exists
    if _chain is not None and event_dict.get("agt_audit"):
        try:
            event = str(event_dict.get("event", ""))
            # ALLOWLIST (not denylist): only known-safe diagnostic fields enter the chain.
            # Anything else (a future bound token/answer/PII) is dropped; we record only
            # HOW MANY were dropped, never their names or values.
            data = {k: v for k, v in event_dict.items()
                    if k in AUDIT_FIELD_ALLOWLIST and k not in ("event", "agt_audit")}
            dropped = sum(1 for k in event_dict
                          if k not in AUDIT_FIELD_ALLOWLIST and k not in ("event", "agt_audit"))
            if dropped:
                data["count_dropped"] = dropped
            _chain.append(event, data)
        except Exception as exc:  # audit must never break request logging
            try:
                _chain.append("audit_write_error", {"error": repr(exc)})
            except Exception:
                pass
    return event_dict


def configure_audit_logging(division: str, role: str, base_dir: str | None = None) -> AuditChain:
    """Create this process's audit chain and hook it into the structlog pipeline.

    Call ONCE at process startup (agent: role='agent'; worker: role='worker')."""
    global _chain
    base = Path(base_dir or os.environ.get("AUDIT_LOG_DIR", "audit_logs"))
    _chain = AuditChain(base / f"{division}_{role}.jsonl")
    cfg = structlog.get_config()
    procs = list(cfg.get("processors") or [])
    if _audit_processor not in procs:
        # insert before the final renderer so the rendered line is unaffected
        procs.insert(max(0, len(procs) - 1), _audit_processor)
        structlog.configure(processors=procs)
    log.info("audit_chain_ready", path=str(_chain.path), role=role, division=division)
    return _chain


def get_chain() -> AuditChain | None:
    return _chain


# ── Read path (FR-8.1 / NFR-9: admin-queryable audit export) ────────────────────
# READ-ONLY surface for the GET /audit endpoint. It never touches the append/anchor
# write path above (the chain stays append-only); it re-reads the on-disk files and
# re-verifies them, so an admin export carries a tamper-evidence status alongside the
# entries. Division-scoped: only the calling division's own <division>_*.jsonl chains
# are read (NFR-2 isolation — one division can never export another's trail).


def read_division_chain(
    division: str,
    base_dir: str | None = None,
    event: str | None = None,
    limit: int | None = None,
) -> dict:
    """Read + verify a division's audit chain(s) for an admin export.

    Reads every ``<division>_<role>.jsonl`` chain under the audit dir (the agent and the
    worker write separate chains), verifies each end-to-end against its external anchor
    (``verify_chain``), and returns the merged entries (chronological by seq, then role)
    plus a per-chain + overall verification status.

    Args:
        division:  the division id whose chains to read (scoping is the caller's job —
                   pass ``settings.division_id`` so a division only ever reads its own).
        base_dir:  audit dir (defaults to ``$AUDIT_LOG_DIR`` then ``audit_logs``, matching
                   :func:`configure_audit_logging`).
        event:     optional exact event-name filter (e.g. ``"access_revoked"``).
        limit:     optional cap on returned entries — the MOST RECENT ``limit`` are kept
                   (verification still covers the full chain, not just the slice).

    Returns a dict::

        {
          "division": <id>,
          "verified": <bool>,                 # True only if EVERY chain verifies
          "chains": [{"file", "role", "ok", "detail", "entries"}, ...],
          "entries": [ {seq, ts, event, data, ...}, ... ],   # filtered/sliced view
          "count": <len(entries)>,
        }

    Never raises on a tampered/corrupt chain — the break is reported via ``verified``
    + the per-chain ``detail`` so the export still returns (the admin needs to SEE that
    the trail was tampered with, not get a 500).
    """
    base = Path(base_dir or os.environ.get("AUDIT_LOG_DIR", "audit_logs"))
    chains: list[dict] = []
    all_entries: list[dict] = []
    overall_ok = True

    files = sorted(f for f in base.glob(f"{division}_*.jsonl")
                   if not f.name.endswith(".anchor.jsonl")) if base.is_dir() else []

    for f in files:
        # Role is the suffix after "<division>_" (e.g. alpha_agent.jsonl -> "agent").
        role = f.stem[len(division) + 1:] if f.stem.startswith(division + "_") else f.stem
        ok, detail = verify_chain(f)
        overall_ok = overall_ok and ok
        entries: list[dict] = []
        try:
            with f.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    rec["role"] = role
                    entries.append(rec)
        except Exception:  # noqa: BLE001 — a read failure must not 500 the export
            pass
        chains.append({"file": f.name, "role": role, "ok": ok,
                       "detail": detail, "entries": len(entries)})
        all_entries.extend(entries)

    # Stable chronological-ish ordering across the per-role chains: by timestamp, then
    # role, then seq (seq is per-chain so it alone can't order across roles).
    all_entries.sort(key=lambda r: (str(r.get("ts", "")), str(r.get("role", "")),
                                    int(r.get("seq", 0))))

    if event:
        all_entries = [r for r in all_entries if r.get("event") == event]
    if limit is not None and limit >= 0:
        all_entries = all_entries[-limit:]

    return {
        "division": division,
        "verified": overall_ok,
        "chains": chains,
        "entries": all_entries,
        "count": len(all_entries),
    }
