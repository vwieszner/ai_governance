"""Mosaic-effect (context-accumulation) guard for retrieved context.

Per-chunk authorization (OpenFGA ReBAC in ``check_auth``) answers "may this user see
THIS chunk?". It cannot answer "may this user see these chunks TOGETHER?" — a user
allowed an HR chunk and, separately, a Finance chunk can still have both folded into
one answer that neither data owner would release as a combination (aggregation /
mosaic risk). This module evaluates the COMBINATION of authorized context before it
reaches the LLM.

It is built on the Agent Governance Toolkit Context Accumulation Governance primitives
(``agent_os.policies.context_envelope`` / ``context_aggregation`` /
``context_accumulation`` / ``data_classification``): every served chunk is folded into
an immutable :class:`ContextEnvelope` (label union + sensitivity max-lattice), then the
organisation-authored :class:`AggregationRuleSet` is evaluated over the accumulated
labels, plus AGT's monotone backstop (``n_category_threshold``) for combinations no rule
covers.

Deterministic + auditable by design (like the other governance tools): chunk labels and
classifications come from an explicit metadata field or from glob rules over existing
chunk metadata (``source`` etc.) declared in YAML — there is no LLM classifier.

Outcomes (per rule, from config):
    escalate — route to the EXISTING approval workflow. The combination is represented by
               a synthetic OpenFGA object ``chunk:mosaic-<rule>`` ("clearance"); the user
               needs ``viewer`` on it (granted by the normal approve path, optionally
               time-bound, or pre-granted to a group by an admin). Owner of that object, if
               set, is the approver; otherwise the approval routes to ``admin``.
    deny     — hard stop; the answer is withheld (no clearance possible).

Fail-closed: a missing/invalid config yields a DENY decision (never a silent allow).
An explicitly empty ``context_aggregation_policy`` setting disables the guard.

Federated answers (cross-division mosaic)
-----------------------------------------
A peer division's answer arrives as TEXT over the DID-signed /a2a/query channel, so the
requesting agent cannot label it from chunk metadata. Instead the ANSWERING peer labels the
chunks it used with this same deterministic classifier (:func:`chunk_labels`) and returns
the label NAMES inside its signed response envelope (``data_labels``; never chunk text/ids).
The requesting agent folds those labels — only from a signature-verified response — into
the same evaluation as a :class:`Contribution`.

Because the graph consults a peer only when local retrieval is empty, a local HR answer and
a federated Finance answer are released by DIFFERENT queries. A per-user, time-windowed
:class:`ReleaseLedger` therefore remembers which labels were released to the user and from
which origin (``local`` or a peer DID); every release is evaluated on the union of its own
labels and the labels released from OTHER origins inside ``federation.window_seconds``.
Same-origin accumulation across queries is deliberately not added here (each origin's own
per-answer guard is unchanged). The ledger is in-process (per replica).

A peer that omits labels (old envelope, guard off, malformed, or not signature-verified) is
handled by ``federation.unlabeled_peer``: ``unknown`` (default) contributes the synthetic
label ``unlabeled-peer`` — it is never silently treated as "no labels" and counts toward the
AGT backstop — ``escalate`` requires the ``mosaic-unlabeled-peer`` clearance, ``deny``
withholds.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import yaml
from agent_os.policies.context_accumulation import accumulate  # type: ignore[import]
from agent_os.policies.context_aggregation import (  # type: ignore[import]
    AggregationRule,
    AggregationRuleSet,
    evaluate_aggregation,
)
from agent_os.policies.context_envelope import (  # type: ignore[import]
    ContextEnvelope,
    envelope_reference,
)
from agent_os.policies.data_classification import DataClassification  # type: ignore[import]

_PKG_ROOT = Path(__file__).resolve().parents[1]
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
CLEARANCE_PREFIX = "mosaic-"
LOCAL_ORIGIN = "local"
# Synthetic label for a peer contribution whose labels are absent / unverified / malformed
# (``federation.unlabeled_peer: unknown``). Participates in rules + the backstop like any label.
UNLABELED_PEER_LABEL = "unlabeled-peer"
UNLABELED_PEER_CLEARANCE = f"{CLEARANCE_PREFIX}unlabeled-peer"
_MAX_PEER_LABELS = 32


class ContextAggregationConfigError(ValueError):
    """The aggregation policy file is missing or invalid (the guard then fails closed)."""


class Outcome(str, Enum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"


# ── Config model ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Classifier:
    """Deterministic metadata → (labels, classification) rule. All ``match`` fields must hit."""

    name: str
    match: dict[str, tuple[str, ...]]   # metadata field -> glob patterns (any matches)
    labels: frozenset[str]
    classification: DataClassification


@dataclass(frozen=True)
class GuardConfig:
    enabled: bool
    default_classification: DataClassification
    classifiers: tuple[Classifier, ...]
    ruleset: AggregationRuleSet
    rule_outcomes: dict[str, Outcome]
    n_category_threshold: int
    backstop_outcome: Outcome
    # Federation: how a peer answer WITHOUT verified labels is treated, and how long a
    # released answer's labels count toward the user's cross-origin accumulation.
    unlabeled_peer: str = "unknown"          # unknown | escalate | deny
    window_seconds: int = 900


_TOP_KEYS = {"version", "name", "description", "enabled", "default_classification",
             "classifiers", "rules", "backstop", "federation"}
_UNLABELED_MODES = ("unknown", "escalate", "deny")


def _classification(value: Any, where: str) -> DataClassification:
    if not isinstance(value, str) or value.strip().upper() not in DataClassification.__members__:
        raise ContextAggregationConfigError(
            f"{where}: unknown classification {value!r} "
            f"(expected one of {', '.join(m.lower() for m in DataClassification.__members__)})")
    return DataClassification[value.strip().upper()]


def _outcome(value: Any, where: str) -> Outcome:
    if value not in (Outcome.ESCALATE.value, Outcome.DENY.value):
        raise ContextAggregationConfigError(f"{where}: outcome must be 'escalate' or 'deny', "
                                            f"got {value!r}")
    return Outcome(value)


def _labels(value: Any, where: str) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise ContextAggregationConfigError(f"{where}: must be a non-empty list of labels")
    out = set()
    for lab in value:
        if not isinstance(lab, str) or not _LABEL_RE.match(lab):
            raise ContextAggregationConfigError(f"{where}: invalid label {lab!r}")
        out.add(lab)
    return frozenset(out)


def parse_config(doc: Any) -> GuardConfig:
    """Validate a parsed YAML document into a :class:`GuardConfig` (strict; raises on error)."""
    if not isinstance(doc, dict):
        raise ContextAggregationConfigError("policy must be a YAML mapping")
    unknown = set(doc) - _TOP_KEYS
    if unknown:
        raise ContextAggregationConfigError(f"unknown top-level keys: {sorted(unknown)}")
    if str(doc.get("version", "")) != "1.0":
        raise ContextAggregationConfigError("version must be \"1.0\"")
    enabled = doc.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ContextAggregationConfigError("enabled must be a boolean")

    default_cls = _classification(doc.get("default_classification", "internal"),
                                  "default_classification")

    classifiers: list[Classifier] = []
    for i, c in enumerate(doc.get("classifiers") or []):
        where = f"classifiers[{i}]"
        if not isinstance(c, dict) or set(c) - {"name", "match", "labels", "classification"}:
            raise ContextAggregationConfigError(f"{where}: invalid classifier entry")
        name = c.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ContextAggregationConfigError(f"{where}: invalid name {name!r}")
        match = c.get("match")
        if not isinstance(match, dict) or not match:
            raise ContextAggregationConfigError(f"{where}: match must be a non-empty mapping")
        parsed_match: dict[str, tuple[str, ...]] = {}
        for fld, pats in match.items():
            if isinstance(pats, str):
                pats = [pats]
            if not isinstance(pats, list) or not pats or not all(
                    isinstance(p, str) and p for p in pats):
                raise ContextAggregationConfigError(
                    f"{where}.match.{fld}: must be a glob or a non-empty list of globs")
            parsed_match[str(fld)] = tuple(p.lower() for p in pats)
        classifiers.append(Classifier(
            name=name, match=parsed_match,
            labels=_labels(c.get("labels"), f"{where}.labels"),
            classification=_classification(c.get("classification"), f"{where}.classification"),
        ))

    rules: list[AggregationRule] = []
    outcomes: dict[str, Outcome] = {}
    for i, r in enumerate(doc.get("rules") or []):
        where = f"rules[{i}]"
        if not isinstance(r, dict) or set(r) - {"name", "all_labels", "sets_sensitivity",
                                                "adds_restrictions", "outcome", "description"}:
            raise ContextAggregationConfigError(f"{where}: invalid rule entry")
        name = r.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ContextAggregationConfigError(f"{where}: invalid name {name!r}")
        if name in outcomes:
            raise ContextAggregationConfigError(f"{where}: duplicate rule name {name!r}")
        all_labels = _labels(r.get("all_labels"), f"{where}.all_labels")
        if len(all_labels) < 2:
            # A one-label "combination" would fire on a single source — that is per-chunk
            # authorization's job (OpenFGA), not an aggregation rule.
            raise ContextAggregationConfigError(f"{where}: all_labels needs >= 2 distinct labels")
        restrictions = r.get("adds_restrictions") or []
        if not isinstance(restrictions, list) or not all(isinstance(x, str) for x in restrictions):
            raise ContextAggregationConfigError(f"{where}.adds_restrictions: list of strings")
        rules.append(AggregationRule(
            name=name, all_labels=all_labels,
            sets_sensitivity=_classification(r.get("sets_sensitivity"),
                                             f"{where}.sets_sensitivity"),
            adds_restrictions=frozenset(restrictions),
        ))
        outcomes[name] = _outcome(r.get("outcome"), f"{where}.outcome")

    backstop = doc.get("backstop") or {}
    if not isinstance(backstop, dict) or set(backstop) - {"n_category_threshold", "outcome"}:
        raise ContextAggregationConfigError("backstop: invalid mapping")
    threshold = backstop.get("n_category_threshold", 0)
    # 0 disables the backstop. AGT escalates when len(labels) >= threshold, so 1 would fire
    # on every labelled single source — reject it (and anything non-int / negative).
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0 \
            or threshold == 1:
        raise ContextAggregationConfigError(
            "backstop.n_category_threshold must be 0 (disabled) or an int >= 2")
    backstop_outcome = _outcome(backstop.get("outcome", "escalate"), "backstop.outcome")

    fed = doc.get("federation") or {}
    if not isinstance(fed, dict) or set(fed) - {"unlabeled_peer", "window_seconds"}:
        raise ContextAggregationConfigError("federation: invalid mapping")
    unlabeled = fed.get("unlabeled_peer", "unknown")
    if unlabeled not in _UNLABELED_MODES:
        raise ContextAggregationConfigError(
            f"federation.unlabeled_peer must be one of {', '.join(_UNLABELED_MODES)}")
    window = fed.get("window_seconds", 900)
    if not isinstance(window, int) or isinstance(window, bool) or window < 0:
        raise ContextAggregationConfigError("federation.window_seconds must be an int >= 0")

    return GuardConfig(
        enabled=enabled, default_classification=default_cls, classifiers=tuple(classifiers),
        ruleset=AggregationRuleSet(rules=tuple(rules)), rule_outcomes=outcomes,
        n_category_threshold=threshold, backstop_outcome=backstop_outcome,
        unlabeled_peer=unlabeled, window_seconds=window,
    )


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else _PKG_ROOT / p


@lru_cache(maxsize=8)
def _load_cached(resolved: str, mtime_ns: int) -> GuardConfig:  # mtime in key → hot reload
    try:
        doc = yaml.safe_load(Path(resolved).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ContextAggregationConfigError(f"YAML parse error: {exc}") from exc
    return parse_config(doc)


def load_config(path: str) -> GuardConfig:
    """Load + validate the policy at *path* (relative paths resolve to the package root)."""
    resolved = _resolve(path)
    try:
        mtime = resolved.stat().st_mtime_ns
    except OSError as exc:
        raise ContextAggregationConfigError(f"policy file not readable: {resolved}") from exc
    return _load_cached(str(resolved), mtime)


# ── Labelling (deterministic) ─────────────────────────────────────────────────


def _field_values(value: Any) -> list[str]:
    """Candidate strings for glob matching: the value and, for paths, its basename."""
    s = str(value).lower()
    base = re.split(r"[\\/]", s)[-1]
    return [s, base] if base != s else [s]


def label_chunk(metadata: dict[str, Any], cfg: GuardConfig) -> tuple[frozenset[str],
                                                                      DataClassification]:
    """Derive (labels, classification) for one chunk from its (trusted) metadata.

    An explicit ``data_labels`` list / ``classification`` string on the chunk is honoured
    (unioned / maxed). Every classifier whose ``match`` fields ALL hit contributes its labels
    and classification. Unmatched chunks get ``default_classification`` and no labels. An
    unrecognised explicit classification fails closed to RESTRICTED.
    """
    md = metadata or {}
    labels: set[str] = set()
    cls = cfg.default_classification
    explicit = md.get("data_labels")
    if isinstance(explicit, list):
        labels |= {str(x).lower() for x in explicit if str(x)}
    if md.get("classification") is not None:
        raw = str(md["classification"]).strip().upper()
        cls = max(cls, DataClassification.__members__.get(raw, DataClassification.RESTRICTED))
    for c in cfg.classifiers:
        hit = True
        for fld, pats in c.match.items():
            if fld not in md or md[fld] is None:
                hit = False
                break
            vals = _field_values(md[fld])
            if not any(fnmatch.fnmatchcase(v, p) for v in vals for p in pats):
                hit = False
                break
        if hit:
            labels |= c.labels
            cls = max(cls, c.classification)
    return frozenset(labels), cls


# ── Decision ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class GuardDecision:
    outcome: Outcome
    reason: str
    labels: frozenset[str] = frozenset()
    sensitivity: DataClassification = DataClassification.PUBLIC
    rules_applied: tuple[str, ...] = ()
    restrictions: frozenset[str] = frozenset()
    # Synthetic OpenFGA object ids the user needs `viewer` on for an ESCALATE to pass.
    clearance_ids: tuple[str, ...] = ()
    # chunk_ids whose labels participate in a triggering rule / the backstop.
    contributing_chunk_ids: tuple[str, ...] = ()
    envelope_ref: Any = field(default=None, compare=False)
    # Human-readable provenance of the contributing context (source names + labels for
    # local chunks; division + DID + labels for peer contributions) — set by
    # :func:`evaluate_combined` so an approver never approves a combination blind.
    sources: tuple[str, ...] = ()


def backstop_clearance_id(labels: Iterable[str]) -> str:
    """Stable clearance id for an uncovered label combination (order-independent)."""
    digest = hashlib.sha256("|".join(sorted(labels)).encode()).hexdigest()[:12]
    return f"{CLEARANCE_PREFIX}backstop-{digest}"


def evaluate_chunks(chunks: list[dict[str, Any]], cfg: GuardConfig,
                    workflow_id: str = "") -> GuardDecision:
    """Fold *chunks* into an AGT ContextEnvelope and decide on the COMBINATION."""
    if not cfg.enabled:
        return GuardDecision(Outcome.ALLOW, "guard_disabled")

    env = ContextEnvelope(envelope_id=f"ctx-{workflow_id or 'adhoc'}", workflow_id=workflow_id)
    per_chunk: dict[str, frozenset[str]] = {}
    for c in chunks:
        labels, cls = label_chunk(c.get("metadata") or {}, cfg)
        per_chunk[str(c.get("chunk_id"))] = labels
        # Post-retrieval accumulation over the ACTUAL labels of authorized, served chunks.
        env = accumulate(env, labels, cls, cfg.ruleset, cfg.n_category_threshold or 10**9)

    agg = evaluate_aggregation(env, cfg.ruleset, cfg.n_category_threshold or 10**9)
    ref = envelope_reference(env)
    base = dict(labels=env.labels, sensitivity=agg.aggregate_sensitivity,
                rules_applied=agg.rules_applied, restrictions=agg.restrictions,
                envelope_ref=ref)

    applied = {r.name: r for r in cfg.ruleset.rules if r.name in agg.rules_applied}

    def _contrib(label_set: frozenset[str]) -> tuple[str, ...]:
        return tuple(sorted(cid for cid, labs in per_chunk.items() if labs & label_set))

    deny = sorted(n for n in applied if cfg.rule_outcomes[n] == Outcome.DENY)
    if deny:
        trig = frozenset().union(*(applied[n].all_labels for n in deny))
        return GuardDecision(Outcome.DENY, "rule:" + ",".join(deny),
                             contributing_chunk_ids=_contrib(trig), **base)
    esc = sorted(n for n in applied if cfg.rule_outcomes[n] == Outcome.ESCALATE)
    if esc:
        trig = frozenset().union(*(applied[n].all_labels for n in esc))
        return GuardDecision(Outcome.ESCALATE, "rule:" + ",".join(esc),
                             clearance_ids=tuple(f"{CLEARANCE_PREFIX}{n}" for n in esc),
                             contributing_chunk_ids=_contrib(trig), **base)
    if agg.escalate:
        # AGT backstop: >= n distinct labels accumulated and no rule governs them.
        reason = f"backstop:{len(env.labels)}_labels>={cfg.n_category_threshold}"
        if cfg.backstop_outcome == Outcome.DENY:
            return GuardDecision(Outcome.DENY, reason,
                                 contributing_chunk_ids=_contrib(env.labels), **base)
        return GuardDecision(Outcome.ESCALATE, reason,
                             clearance_ids=(backstop_clearance_id(env.labels),),
                             contributing_chunk_ids=_contrib(env.labels), **base)
    return GuardDecision(Outcome.ALLOW, "no_rule_matched", **base)


def evaluate(chunks: list[dict[str, Any]], policy_path: str,
             workflow_id: str = "") -> GuardDecision:
    """Load the configured policy and evaluate. FAIL-CLOSED: config errors → DENY."""
    if not policy_path:
        return GuardDecision(Outcome.ALLOW, "guard_disabled")
    try:
        cfg = load_config(policy_path)
    except ContextAggregationConfigError as exc:
        return GuardDecision(Outcome.DENY, f"config_error: {exc}"[:300])
    return evaluate_chunks(chunks, cfg, workflow_id)


# ── Federation: peer-reported labels + cross-origin release ledger ─────────────


def chunk_labels(chunks: list[dict[str, Any]], policy_path: str) -> list[str] | None:
    """Label NAMES of the chunks an answer was generated from (the ANSWERING peer's side).

    Returned inside the DID-signed /a2a/query response so the requesting division can
    evaluate the cross-division combination. Labels only — never chunk text or ids.
    ``None`` (→ the field is omitted, the requester applies its unlabeled-peer fail mode)
    when the guard is switched off by an empty path or the policy cannot be loaded.
    """
    if not policy_path:
        return None
    try:
        cfg = load_config(policy_path)
    except ContextAggregationConfigError:
        return None
    out: set[str] = set()
    for c in chunks:
        out |= label_chunk(c.get("metadata") or {}, cfg)[0]
    return sorted(out)


def validate_peer_labels(raw: Any) -> frozenset[str] | None:
    """Strictly parse a peer-reported ``data_labels`` value; ``None`` = treat as unlabeled.

    Anything other than a bounded list of well-formed label strings (absent field from an
    old-envelope peer, wrong type, junk entries) is NOT trusted as "no labels".
    """
    if not isinstance(raw, list) or len(raw) > _MAX_PEER_LABELS:
        return None
    out: set[str] = set()
    for lab in raw:
        if not isinstance(lab, str) or not _LABEL_RE.match(lab):
            return None
        out.add(lab)
    return frozenset(out)


@dataclass(frozen=True)
class Contribution:
    """Context released (or about to be released) to the user that is NOT a local chunk of
    the current query: a peer answer, or an earlier release recorded in the ledger."""

    origin: str                              # LOCAL_ORIGIN or the peer's verified DID
    division: str = ""
    labels: frozenset[str] | None = None     # None = unlabeled (see federation.unlabeled_peer)
    sources: tuple[str, ...] = ()            # local source names (never for peers)
    verified: bool = True                    # labels came from a signature-verified response

    def effective_labels(self) -> frozenset[str] | None:
        return self.labels if self.verified else None


def _source_name(md: dict[str, Any]) -> str:
    raw = str((md or {}).get("source") or "")
    return re.split(r"[\\/]", raw)[-1] if raw else ""


def local_release(chunks: list[dict[str, Any]], cfg: GuardConfig,
                  division: str = "") -> Contribution | None:
    """Ledger entry for released LOCAL chunks (labelled chunks only), or None."""
    labels: set[str] = set()
    sources: list[str] = []
    for c in chunks:
        md = c.get("metadata") or {}
        labs = label_chunk(md, cfg)[0]
        if labs:
            labels |= labs
            name = _source_name(md)
            if name and name not in sources:
                sources.append(name)
    if not labels:
        return None
    return Contribution(origin=LOCAL_ORIGIN, division=division, labels=frozenset(labels),
                        sources=tuple(sources))


def _fmt_labels(labels: Iterable[str]) -> str:
    return "[" + ", ".join(sorted(labels)) + "]"


def evaluate_combined(local_chunks: list[dict[str, Any]], contributions: list[Contribution],
                      cfg: GuardConfig, workflow_id: str = "",
                      local_division: str = "") -> GuardDecision:
    """Evaluate local chunks of this query + peer / earlier-release contributions TOGETHER.

    Each contribution is folded into the same AGT envelope as a synthetic chunk carrying its
    labels, so the existing rules + backstop decide on the union. An unlabeled contribution
    follows ``cfg.unlabeled_peer``. A non-ALLOW decision carries ``sources`` (provenance of
    the contributing context) for the approval request.
    """
    if not cfg.enabled:
        return GuardDecision(Outcome.ALLOW, "guard_disabled")
    chunks = list(local_chunks)
    synth: dict[str, Contribution] = {}
    unlabeled_ids: list[str] = []
    for i, contrib in enumerate(contributions):
        cid = f"contrib:{i}"
        labs = contrib.effective_labels()
        if labs is None:
            unlabeled_ids.append(cid)
            labs = (frozenset({UNLABELED_PEER_LABEL}) if cfg.unlabeled_peer == "unknown"
                    else frozenset())
        synth[cid] = replace(contrib, labels=labs, verified=True)
        chunks.append({"chunk_id": cid, "metadata": {"data_labels": sorted(labs)}})

    d = evaluate_chunks(chunks, cfg, workflow_id)
    if unlabeled_ids and cfg.unlabeled_peer == "deny" and d.outcome != Outcome.DENY:
        d = replace(d, outcome=Outcome.DENY, reason="unlabeled_peer:deny", clearance_ids=(),
                    contributing_chunk_ids=tuple(sorted(set(d.contributing_chunk_ids)
                                                        | set(unlabeled_ids))))
    elif unlabeled_ids and cfg.unlabeled_peer == "escalate" and d.outcome != Outcome.DENY:
        d = replace(
            d, outcome=Outcome.ESCALATE,
            reason=d.reason if d.outcome == Outcome.ESCALATE else "unlabeled_peer:escalate",
            clearance_ids=tuple(dict.fromkeys(d.clearance_ids + (UNLABELED_PEER_CLEARANCE,))),
            contributing_chunk_ids=tuple(sorted(set(d.contributing_chunk_ids)
                                                | set(unlabeled_ids))))
    if d.outcome == Outcome.ALLOW:
        return d

    ids = set(d.contributing_chunk_ids)
    sources: list[str] = []
    here = local_division or LOCAL_ORIGIN
    for c in local_chunks:
        if str(c.get("chunk_id")) in ids:
            md = c.get("metadata") or {}
            sources.append(f"{here}: {_source_name(md) or c.get('chunk_id')} "
                           f"{_fmt_labels(label_chunk(md, cfg)[0])}")
    for cid, contrib in synth.items():
        if cid not in ids:
            continue
        if contrib.origin == LOCAL_ORIGIN:
            names = ", ".join(contrib.sources) or "earlier answer"
            sources.append(f"{contrib.division or here} (earlier answer): {names} "
                           f"{_fmt_labels(contrib.labels or ())}")
        else:
            tag = " (unlabeled/unverified)" if cid in unlabeled_ids else ""
            sources.append(f"peer {contrib.division or 'unknown-division'} ({contrib.origin})"
                           f"{tag}: {_fmt_labels(contrib.labels or ())}")
    return replace(d, sources=tuple(dict.fromkeys(sources)))


class ReleaseLedger:
    """Per-user, time-windowed record of the labels RELEASED to a user, by origin.

    In-process (per replica) and bounded. Only provenance is kept (origin, division,
    label names, local source names) — never chunk text.
    """

    _MAX_PER_USER = 64

    def __init__(self) -> None:
        self._entries: dict[str, list[tuple[float, Contribution]]] = {}
        self._lock = threading.Lock()

    def record(self, user_id: str, contrib: Contribution, now: float | None = None) -> None:
        ts = time.time() if now is None else now
        with self._lock:
            rows = self._entries.setdefault(user_id, [])
            rows.append((ts, contrib))
            del rows[:-self._MAX_PER_USER]

    def others(self, user_id: str, exclude_origin: str, window_seconds: int,
               now: float | None = None) -> list[Contribution]:
        """Releases to *user_id* from origins other than *exclude_origin* within the window."""
        if window_seconds <= 0:
            return []
        ts = time.time() if now is None else now
        with self._lock:
            rows = [(t, c) for t, c in self._entries.get(user_id, [])
                    if ts - t <= window_seconds]
            if rows:
                self._entries[user_id] = rows
            else:
                self._entries.pop(user_id, None)
        return list(dict.fromkeys(c for _, c in rows if c.origin != exclude_origin))

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


LEDGER = ReleaseLedger()
