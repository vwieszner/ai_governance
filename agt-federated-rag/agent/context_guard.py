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
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
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


_TOP_KEYS = {"version", "name", "description", "enabled", "default_classification",
             "classifiers", "rules", "backstop"}


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

    return GuardConfig(
        enabled=enabled, default_classification=default_cls, classifiers=tuple(classifiers),
        ruleset=AggregationRuleSet(rules=tuple(rules)), rule_outcomes=outcomes,
        n_category_threshold=threshold, backstop_outcome=backstop_outcome,
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
