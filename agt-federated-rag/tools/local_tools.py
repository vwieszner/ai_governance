"""In-process governed tool registry — real, deterministic AI-governance tools.

The governed MCP executor (``tools.mcp.call_mcp_tool``) is transport-agnostic: it runs
the three governance gates (policy default-deny → McpAuthPolicy gateway → the §4.2
no-credential boundary) and then delegates the actual call to an injected ``caller``.
Until now no in-process ``caller`` existed, so ``call_mcp_tool`` always raised "no MCP
transport configured". This module provides that transport for a small set of SAFE,
dependency-light, pure-compute AI-governance tools so the agent can actually EXECUTE
real governance work end-to-end through every gate — and so different divisions can
advertise DIFFERENT capabilities (``tool.pii``, ``tool.compliance``, ``tool.risk``,
``tool.classify``, ``tool.fincheck``) for cross-agent tool delegation.

The five tools are genuine governance primitives, not toys:
  - ``tool.pii`` (server ``pii-scan``, tool ``scan``) — a PII / DLP screen: detect +
    classify + redact emails, phones, SSNs, Luhn-valid cards, IBANs, IPv4 in free text.
  - ``tool.compliance`` (server ``compliance-lookup``, tool ``lookup``) — a deterministic
    obligation KB: map a governance topic (high-risk, transparency, human oversight, …) to
    the relevant EU AI Act / GDPR articles. On-theme with the seeded eu_ai_act / gdpr docs.
  - ``tool.risk`` (server ``risk-score``, tool ``assess``) — an EU AI Act risk-TIER
    classifier: map an AI-system description to unacceptable|high|limited|minimal with a
    score, rationale, and the obligations that tier triggers.
  - ``tool.classify`` (server ``data-classify``, tool ``classify``) — a data-SENSITIVITY
    classifier: assign Public|Internal|Confidential|Restricted from content signals
    (Classification markers, credential patterns, and PII via the shared DLP detectors).
  - ``tool.fincheck`` (server ``fin-check``, tool ``screen``) — a finance / AML transaction
    screen: check a transaction against a sanctions watchlist, the large-transaction
    disclosure threshold, and currency/jurisdiction risk. On-theme with the seeded
    q4_financial_results / AML governance.

PER-DIVISION ASSIGNMENT (so divisions genuinely differ). ``AGT_LOCAL_TOOLS`` is a CSV of
the capabilities a division serves — either full capability ids (``tool.pii``) or the
short names (``pii``). Unset/empty → serves ALL tools (back-compat default). A division
launched with ``AGT_LOCAL_TOOLS="tool.pii"`` serves ONLY the PII screen (the "DLP division"
pattern): it advertises only ``tool.pii``, its gateway registers only ``pii-scan``, and
``server_for_capability("tool.compliance")`` is None — so its ``solve_with_tools`` knows it
lacks compliance locally and DELEGATES it to a peer. Each department can own a distinct
subset, so the four tools spread across divisions for the cross-agent demo.

Each enabled local server is registered into ``settings.mcp_servers`` exactly like a real
MCP server (so the gateway treats it as configured). It authenticates with the agent's own
SERVICE credential — ``auth_mode: "service_rebac"`` — which is why ``url`` is empty,
``require_tls`` is False (the call never leaves the process) and the gateway auth method
is ``bearer`` (a service credential; the gateway has no "in-process" method). No network,
no filesystem: every tool is a deterministic function of its arguments.
"""
from __future__ import annotations

import os
import re
from typing import Any, Callable

from tools.mcp import McpToolError

# ── input bounds (DoS guard) ──────────────────────────────────────────────────
# Every tool caps its free-text input length so a single call cannot make the regex
# engine / KB walk do unbounded work. A short governance document scan stays well under
# this; only a pathological payload trips it (ValueError, surfaced as McpToolError by the
# governed path). Separate from main.py's outbound arg-byte cap — this is the tool's own
# self-protection.
_MAX_PII_TEXT_LEN = 20_000
_MAX_COMPLIANCE_TOPIC_LEN = 512
_MAX_RISK_DESC_LEN = 20_000
_MAX_CLASSIFY_TEXT_LEN = 20_000
_MAX_COUNTERPARTY_LEN = 256


# ── tool.pii: a real PII / DLP screen ─────────────────────────────────────────
# Detect + classify + redact PII with regex + light validation. SECURITY: the RAW PII
# value NEVER appears in findings, counts, the redacted text spans, or any log — only a
# last-4 mask (e.g. "****1234"). Each finding carries {type, masked}; the caller (and the
# audit log) only ever see masked values. This is the no-leak invariant of a DLP tool.

# Order matters: more specific / structured patterns first so an SSN-shaped run inside a
# longer digit string is classified before the generic number patterns. Each entry is
# (type, compiled regex, optional validator(match) -> bool). A validator returning False
# means "looks like this type but fails validation" → NOT a finding (e.g. Luhn-invalid
# card, so we never flag a random 16-digit id as a credit card).
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# US SSN NNN-NN-NNNN (require the dashes so we don't grab arbitrary 9-digit runs).
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Credit card: 13–19 digit runs, optionally separated by single spaces or hyphens in
# groups. Validated by Luhn below so Luhn-invalid numbers are NOT flagged as cards.
_CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
# IBAN: 2 letters + 2 check digits + 11–30 alphanumerics (broad but structured).
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
# Phone: international (+CC …) or US-style; require enough digits to avoid grabbing years.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{1,4}\)[\s.\-]?)?\d{2,4}(?:[\s.\-]\d{2,4}){2,4}(?!\d)"
)
# IPv4 dotted-quad with each octet 0–255.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def _luhn_valid(digits: str) -> bool:
    """True iff ``digits`` (a string of 0-9) satisfies the Luhn checksum. Used to gate
    credit-card findings so a Luhn-INVALID number is never flagged as a card."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _mask(value: str) -> str:
    """Mask a PII value to its last 4 characters (e.g. "****1234"). For values with fewer
    than 4 trailing alphanumerics we still only reveal what's left, never the whole value.
    NEVER returns the raw value — this is the only form a finding/log may carry."""
    tail = re.sub(r"[^A-Za-z0-9]", "", value)[-4:]
    return "****" + tail


# (type, regex, validator). Validator None → every match is a finding. The list order is
# the classification priority; once a span is consumed by an earlier type it is not
# re-matched by a later, more generic one.
_PII_PATTERNS: list[tuple[str, re.Pattern, Callable[[str], bool] | None]] = [
    ("EMAIL", _EMAIL_RE, None),
    ("SSN", _SSN_RE, None),
    ("CARD", _CARD_RE, _luhn_valid),
    ("IBAN", _IBAN_RE, None),
    ("IPV4", _IPV4_RE, None),
    ("PHONE", _PHONE_RE, None),
]


def _detect_pii_spans(text: str) -> list[tuple[int, int, str]]:
    """Core PII detector: return the non-overlapping ``(start, end, type)`` spans, earliest
    pattern wins, validators applied (e.g. Luhn for CARD). Shared by ``pii_scan`` (which
    masks + redacts them) and ``classify`` (which uses only the TYPES as a sensitivity
    signal). Returns spans sorted by start offset. NEVER returns the raw values — callers
    that need a masked form slice ``text`` themselves."""
    claimed: list[tuple[int, int, str]] = []  # (start, end, type)

    def _overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e, _ in claimed)

    for ptype, pattern, validator in _PII_PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.start(), m.end()
            if _overlaps(start, end):
                continue
            value = m.group(0)
            if validator is not None and not validator(value):
                continue
            claimed.append((start, end, ptype))

    claimed.sort()
    return claimed


def pii_scan(arguments: dict) -> dict:
    """Screen ``{"text": str}`` for PII (real DLP tool).

    Returns ``{"has_pii": bool, "findings": [{"type", "masked"}], "redacted": str,
    "counts": {type: n}}`` where ``masked`` reveals only the last 4 chars and ``redacted``
    replaces each PII span with ``[TYPE_REDACTED]``. The RAW value is never placed in the
    output or logs. Raises ValueError on a non-string or oversized input (DoS guard)."""
    text = arguments.get("text")
    if not isinstance(text, str):
        raise ValueError("'text' must be a string")
    if len(text) > _MAX_PII_TEXT_LEN:
        raise ValueError(f"text too long ({len(text)} > {_MAX_PII_TEXT_LEN}) — refusing (DoS guard)")

    # Collect non-overlapping spans (earliest pattern wins, validators applied).
    claimed = _detect_pii_spans(text)
    findings: list[dict[str, str]] = []
    counts: dict[str, int] = {}
    # Build the redacted text by replacing each claimed span with its [TYPE_REDACTED] marker,
    # walking left to right so offsets stay valid.
    pieces: list[str] = []
    cursor = 0
    for start, end, ptype in claimed:
        pieces.append(text[cursor:start])
        pieces.append(f"[{ptype}_REDACTED]")
        cursor = end
        findings.append({"type": ptype, "masked": _mask(text[start:end])})
        counts[ptype] = counts.get(ptype, 0) + 1
    pieces.append(text[cursor:])
    redacted = "".join(pieces)

    return {
        "has_pii": bool(findings),
        "findings": findings,
        "redacted": redacted,
        "counts": counts,
    }


# ── tool.compliance: a deterministic obligation lookup ────────────────────────
# A small, realistic KB mapping governance TOPICS → the obligations they trigger under the
# EU AI Act and GDPR. Keyword-matched (case-insensitive substring) so "what about automated
# decisions?" hits the "automated decision" topic. A clean miss returns empty matches — it
# NEVER raises (a no-result lookup is a normal, expected outcome, not an error).
_COMPLIANCE_KB: dict[str, tuple[str, ...]] = {}


def _kb_entry(framework: str, article: str, summary: str) -> dict[str, str]:
    return {"framework": framework, "article": article, "summary": summary}


# topic keyword -> list of obligation matches. Kept small (10 topics) but on-theme with the
# seeded eu_ai_act_requirements / gdpr_ai_obligations docs.
_COMPLIANCE_TOPICS: dict[str, list[dict[str, str]]] = {
    "high-risk": [
        _kb_entry("EU AI Act", "Art. 6", "Classifies AI systems as high-risk by use case "
                  "(Annex III) or as a safety component; high-risk status triggers the full "
                  "Chapter III obligations."),
        _kb_entry("EU AI Act", "Art. 9", "Requires a documented risk-management system run "
                  "across the entire lifecycle of a high-risk AI system."),
    ],
    "transparency": [
        _kb_entry("EU AI Act", "Art. 13", "High-risk systems must be transparent enough that "
                  "deployers can interpret output and use the system appropriately; "
                  "instructions for use are mandatory."),
        _kb_entry("EU AI Act", "Art. 50", "Transparency obligations for AI that interacts with "
                  "people, generates synthetic content, or is an emotion/biometric system "
                  "(users must be informed)."),
        _kb_entry("GDPR", "Art. 13-14", "Data subjects must be informed about the existence of "
                  "automated decision-making and the logic involved."),
    ],
    "human oversight": [
        _kb_entry("EU AI Act", "Art. 14", "High-risk AI must be designed for effective human "
                  "oversight, including the ability to intervene or halt the system."),
    ],
    "automated decision": [
        _kb_entry("GDPR", "Art. 22", "A person has the right not to be subject to a decision "
                  "based solely on automated processing that produces legal or similarly "
                  "significant effects, absent specific legal bases + safeguards."),
        _kb_entry("EU AI Act", "Art. 14", "Human oversight measures must let a human override or "
                  "reverse an automated outcome from a high-risk system."),
    ],
    "data retention": [
        _kb_entry("GDPR", "Art. 5(1)(e)", "Storage limitation: personal data kept in identifiable "
                  "form no longer than necessary for the purpose."),
        _kb_entry("EU AI Act", "Art. 12", "Automatic logging (records/event logs) of high-risk AI "
                  "must be retained for an appropriate period to ensure traceability."),
    ],
    "biometric": [
        _kb_entry("EU AI Act", "Art. 5", "Prohibits certain biometric practices (e.g. untargeted "
                  "scraping for facial-recognition databases; real-time remote biometric ID in "
                  "public spaces save narrow exceptions)."),
        _kb_entry("GDPR", "Art. 9", "Biometric data for unique identification is a special "
                  "category requiring an explicit Art. 9(2) legal basis."),
    ],
    "data governance": [
        _kb_entry("EU AI Act", "Art. 10", "Training, validation, and testing data must meet "
                  "quality criteria and be examined for bias; data-governance practices are "
                  "mandatory for high-risk AI."),
        _kb_entry("GDPR", "Art. 5(1)(a-c)", "Lawfulness, fairness, transparency; purpose "
                  "limitation; data minimisation govern any personal data used."),
    ],
    "accuracy": [
        _kb_entry("EU AI Act", "Art. 15", "High-risk AI must achieve appropriate accuracy, "
                  "robustness, and cybersecurity, with metrics declared in the instructions."),
        _kb_entry("GDPR", "Art. 5(1)(d)", "Personal data must be accurate and kept up to date; "
                  "inaccurate data erased or rectified."),
    ],
    "record keeping": [
        _kb_entry("EU AI Act", "Art. 12", "High-risk AI must technically allow automatic logging "
                  "of events over its lifetime (traceability)."),
        _kb_entry("EU AI Act", "Art. 11", "Technical documentation must be drawn up before the "
                  "system is placed on the market and kept up to date."),
    ],
    "data subject rights": [
        _kb_entry("GDPR", "Art. 15-22", "Access, rectification, erasure, restriction, "
                  "portability, objection, and the Art. 22 automated-decision safeguards."),
    ],
}


def compliance_lookup(arguments: dict) -> dict:
    """Look up governance obligations for ``{"topic": str}`` against the deterministic KB.

    Returns ``{"topic": str, "matches": [{"framework", "article", "summary"}]}``. A topic
    that matches nothing returns ``matches: []`` — a clean miss NEVER raises. Raises
    ValueError only on a non-string or oversized topic (DoS guard)."""
    topic = arguments.get("topic")
    if not isinstance(topic, str):
        raise ValueError("'topic' must be a string")
    if len(topic) > _MAX_COMPLIANCE_TOPIC_LEN:
        raise ValueError(
            f"topic too long ({len(topic)} > {_MAX_COMPLIANCE_TOPIC_LEN}) — refusing (DoS guard)"
        )

    q = topic.lower()
    matches: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for keyword, entries in _COMPLIANCE_TOPICS.items():
        if keyword in q:
            for entry in entries:
                key = (entry["framework"], entry["article"])
                if key not in seen:
                    seen.add(key)
                    matches.append(entry)
    return {"topic": topic, "matches": matches}


# ── tool.risk: deterministic EU AI Act risk-tier classifier ───────────────────
# Map a description of an AI system/use case to one of the four EU AI Act risk TIERS by
# deterministic keyword/signal matching. The four tiers (highest first):
#   unacceptable — prohibited practices (Art. 5): social scoring, untargeted facial scraping,
#                  manipulative/subliminal techniques, real-time remote biometric ID in public.
#   high         — Annex III use cases (Art. 6): biometric ID, critical infrastructure,
#                  education/employment/credit scoring, law enforcement, migration, justice.
#   limited      — transparency-only obligations (Art. 50): chatbots, emotion recognition,
#                  deepfakes / generated content, recommender systems.
#   minimal      — everything else (spam filters, inventory optimisation, games): no mandatory
#                  obligations beyond voluntary codes.
# Signals are weighted; the highest-tier signal present wins (a prohibited signal dominates a
# high one, etc.). On an empty/unmatched description we default CONSERVATIVELY to "limited"
# (transparency obligations) rather than "minimal", and say so in the rationale — a clean miss
# NEVER raises.
_RISK_SIGNALS: dict[str, tuple[str, ...]] = {
    "unacceptable": (
        "social scoring", "social credit", "subliminal", "manipulative", "manipulation of",
        "exploit vulnerabilities", "untargeted scraping", "facial recognition database",
        "real-time remote biometric", "predictive policing", "emotion recognition in the workplace",
        "mass surveillance",
    ),
    "high": (
        "biometric identification", "biometric categorisation", "biometric categorization",
        "critical infrastructure", "safety component", "medical device", "diagnosis",
        "recruitment", "hiring", "cv screening", "resume screening", "employee monitoring",
        "credit scoring", "creditworthiness", "loan approval", "insurance pricing",
        "exam scoring", "student assessment", "admissions", "law enforcement", "border control",
        "migration", "asylum", "judicial", "sentencing", "essential services eligibility",
    ),
    "limited": (
        "chatbot", "chat bot", "conversational agent", "virtual assistant", "recommendation",
        "recommender", "deepfake", "deep fake", "synthetic media", "generated content",
        "generative", "emotion recognition", "image generation", "text generation",
    ),
    "minimal": (
        "spam filter", "spam detection", "inventory", "demand forecasting", "predictive maintenance",
        "video game", "ranking search results", "ad targeting optimisation",
    ),
}
# Numeric score per tier (0–100), for an at-a-glance severity gauge.
_RISK_SCORES = {"unacceptable": 100, "high": 75, "limited": 40, "minimal": 10}
# The obligations each tier triggers (short, on-theme with the compliance KB above).
_RISK_OBLIGATIONS: dict[str, tuple[str, ...]] = {
    "unacceptable": (
        "PROHIBITED under EU AI Act Art. 5 — the system may not be placed on the market or "
        "put into service.",
        "Halt deployment; no conformity route exists for a prohibited practice.",
    ),
    "high": (
        "Risk-management system across the lifecycle (Art. 9).",
        "Data governance + bias examination of training/validation/test data (Art. 10).",
        "Technical documentation + automatic logging for traceability (Art. 11-12).",
        "Transparency + instructions for use (Art. 13); effective human oversight (Art. 14).",
        "Accuracy, robustness, cybersecurity (Art. 15); conformity assessment before market.",
    ),
    "limited": (
        "Transparency obligations (Art. 50): inform users they are interacting with AI / that "
        "content is AI-generated.",
        "Label synthetic/deepfake content; disclose emotion-recognition or biometric use.",
    ),
    "minimal": (
        "No mandatory obligations beyond voluntary codes of conduct (Art. 95).",
        "Follow general data-protection (GDPR) duties if personal data is processed.",
    ),
}
_RISK_TIER_ORDER = ("unacceptable", "high", "limited", "minimal")


def risk_assess(arguments: dict) -> dict:
    """Classify an AI system/use-case ``{"description": str}`` into an EU AI Act risk TIER.

    Returns ``{"tier", "score", "rationale", "obligations": [...]}`` where ``tier`` is one of
    unacceptable|high|limited|minimal, ``score`` is 0–100, and ``obligations`` are the duties
    that tier triggers. Deterministic keyword matching: the highest-severity signal present
    wins. NEVER raises on unknown input — defaults conservatively to "limited" with a rationale.
    Raises ValueError only on a non-string or oversized description (DoS guard)."""
    description = arguments.get("description")
    if not isinstance(description, str):
        raise ValueError("'description' must be a string")
    if len(description) > _MAX_RISK_DESC_LEN:
        raise ValueError(
            f"description too long ({len(description)} > {_MAX_RISK_DESC_LEN}) — refusing (DoS guard)"
        )

    q = description.lower()
    # Walk tiers highest-severity first; the first tier with a matched signal wins.
    for tier in _RISK_TIER_ORDER:
        hits = [s for s in _RISK_SIGNALS[tier] if s in q]
        if hits:
            rationale = (f"Matched {tier} EU AI Act signal(s): "
                         f"{', '.join(repr(h) for h in hits[:5])}.")
            return {
                "tier": tier,
                "score": _RISK_SCORES[tier],
                "rationale": rationale,
                "obligations": list(_RISK_OBLIGATIONS[tier]),
            }
    # Conservative default on a clean miss (no recognised signal): transparency tier.
    return {
        "tier": "limited",
        "score": _RISK_SCORES["limited"],
        "rationale": "No specific risk signal matched; defaulting CONSERVATIVELY to 'limited' "
                     "(transparency obligations). A human should confirm the tier.",
        "obligations": list(_RISK_OBLIGATIONS["limited"]),
    }


# ── tool.classify: deterministic data-sensitivity classifier ──────────────────
# Assign a four-level data SENSITIVITY label from content signals, on-theme with the seeded
# docs' "Classification:" headers. Labels (most sensitive first):
#   Restricted   — credentials/secrets OR regulated PII (SSN, credit card, IBAN) present, OR a
#                  "strictly confidential" / "restricted" marker.
#   Confidential — a "confidential" marker, or other PII (email/phone/IP) present.
#   Internal     — an "internal" / "internal use only" marker (no PII).
#   Public       — nothing sensitive detected, or an explicit "public" marker.
# We REUSE the PII detectors (via _detect_pii_spans) so the classifier and the DLP screen
# agree on what counts as PII. Deterministic; never raises on unknown input.
_CRED_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_\s-]?key|access[_\s-]?token|private[_\s-]?key|"
    r"client[_\s-]?secret|bearer\s+[A-Za-z0-9._\-]+)\b"
)
# Regulated PII types that push a document to Restricted (vs. merely Confidential).
_RESTRICTED_PII = frozenset({"SSN", "CARD", "IBAN"})


def classify(arguments: dict) -> dict:
    """Classify the data-sensitivity of ``{"text": str}``.

    Returns ``{"label", "signals": [...], "handling": "<one-line guidance>"}`` where ``label``
    is Public|Internal|Confidential|Restricted. Deterministic content signals: explicit
    Classification markers, credential/secret patterns, and PII (reusing the DLP detectors).
    The most-sensitive signal wins. SECURITY: ``signals`` describe WHAT was found (e.g.
    "regulated PII: CARD"), never the raw value. Raises ValueError only on a non-string or
    oversized input (DoS guard)."""
    text = arguments.get("text")
    if not isinstance(text, str):
        raise ValueError("'text' must be a string")
    if len(text) > _MAX_CLASSIFY_TEXT_LEN:
        raise ValueError(
            f"text too long ({len(text)} > {_MAX_CLASSIFY_TEXT_LEN}) — refusing (DoS guard)"
        )

    low = text.lower()
    signals: list[str] = []
    # Score each label; the highest reached wins. Start at Public.
    label = "Public"

    def _raise_to(new_label: str) -> None:
        nonlocal label
        order = ["Public", "Internal", "Confidential", "Restricted"]
        if order.index(new_label) > order.index(label):
            label = new_label

    # Explicit classification markers (the seeded docs carry "Classification:" headers).
    if "strictly confidential" in low or re.search(r"(?i)classification:\s*restricted", text):
        signals.append("explicit marker: strictly confidential / restricted")
        _raise_to("Restricted")
    if re.search(r"(?i)classification:\s*confidential", text) or "confidential" in low:
        signals.append("explicit marker: confidential")
        _raise_to("Confidential")
    if re.search(r"(?i)classification:\s*internal", text) or "internal use only" in low:
        signals.append("explicit marker: internal")
        _raise_to("Internal")
    if re.search(r"(?i)classification:\s*public", text):
        signals.append("explicit marker: public")

    # Credentials / secrets → Restricted (a leaked secret is the most sensitive case).
    if _CRED_RE.search(text):
        signals.append("credential/secret pattern present")
        _raise_to("Restricted")

    # PII (reuse the DLP detectors). Regulated PII → Restricted; other PII → Confidential.
    pii_types = {ptype for _s, _e, ptype in _detect_pii_spans(text)}
    restricted_pii = sorted(pii_types & _RESTRICTED_PII)
    other_pii = sorted(pii_types - _RESTRICTED_PII)
    if restricted_pii:
        signals.append(f"regulated PII present: {', '.join(restricted_pii)}")
        _raise_to("Restricted")
    if other_pii:
        signals.append(f"PII present: {', '.join(other_pii)}")
        _raise_to("Confidential")

    handling = {
        "Public":       "No restrictions; may be shared externally.",
        "Internal":     "Share within the organisation only; do not publish externally.",
        "Confidential": "Need-to-know access; encrypt in transit and at rest; do not forward.",
        "Restricted":   "Strict need-to-know; encrypt + audit access; never email or log in the "
                        "clear; PII/secret handling controls apply.",
    }[label]
    return {"label": label, "signals": signals, "handling": handling}


# ── tool.fincheck: deterministic finance / AML transaction screen ─────────────
# A real finance-governance primitive: screen a transaction against three deterministic
# controls and return whether it is flagged, whether disclosure is required, and a risk band
# with the reasons that fired. On-theme with the seeded q4_financial_results / AML governance.
#   1. SANCTIONS — counterparty (normalised, case-insensitive) matches a sample watchlist of
#      fictitious sanctioned entities → flagged, high risk.
#   2. DISCLOSURE THRESHOLD — amount > 10000 (in ANY currency) → disclosure_required (large-
#      transaction reporting, e.g. CTR-style).
#   3. CURRENCY/JURISDICTION RISK — a higher-risk currency code → elevated (at least medium)
#      risk.
# SECURITY: the tool only ever echoes the inputs it was given (amount + currency); ``reasons``
# describe WHAT matched ("counterparty on sanctions watchlist"), never any secret. Deterministic;
# never raises on normal input — ValueError only on bad TYPES or an oversized counterparty.
_SANCTIONS_WATCHLIST = frozenset({
    "volkov holdings", "redline imports", "acme shell ltd", "north star trading",
    "grayport logistics",
})
# Disclosure threshold for large-transaction reporting (any currency).
_DISCLOSURE_THRESHOLD = 10_000
# Higher-risk currency codes (sanctioned / high-AML-risk jurisdictions — illustrative set).
_HIGH_RISK_CURRENCIES = frozenset({"KPW", "IRR", "SYP", "CUP"})


def fin_check(arguments: dict) -> dict:
    """Screen a transaction ``{"amount": number, "currency": str, "counterparty": str}`` for
    AML / finance-governance controls.

    Returns ``{"flagged": bool, "disclosure_required": bool, "risk": "low"|"medium"|"high",
    "reasons": [str,...], "amount": number, "currency": str}``. Deterministic checks: sanctions
    watchlist (→ flagged + high), >10000 disclosure threshold, higher-risk currency (→ ≥medium).
    Never raises on normal input — ValueError only on bad types or an oversized counterparty."""
    amount = arguments.get("amount")
    currency = arguments.get("currency")
    counterparty = arguments.get("counterparty")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("'amount' must be a number")
    if not isinstance(currency, str) or not isinstance(counterparty, str):
        raise ValueError("'currency' and 'counterparty' must be strings")
    if len(counterparty) > _MAX_COUNTERPARTY_LEN:
        raise ValueError(
            f"counterparty too long ({len(counterparty)} > {_MAX_COUNTERPARTY_LEN}) — refusing"
        )

    reasons: list[str] = []
    flagged = False
    disclosure_required = False
    # Risk escalates monotonically: start low, raise to medium/high as controls fire.
    risk_rank = {"low": 0, "medium": 1, "high": 2}
    risk = "low"

    def _raise_risk(level: str) -> None:
        nonlocal risk
        if risk_rank[level] > risk_rank[risk]:
            risk = level

    # 1. Sanctions watchlist (normalise whitespace + case for the comparison).
    normalised_cp = " ".join(counterparty.lower().split())
    if normalised_cp in _SANCTIONS_WATCHLIST:
        flagged = True
        _raise_risk("high")
        reasons.append("counterparty on sanctions watchlist")

    # 2. Large-transaction disclosure threshold (any currency).
    if amount > _DISCLOSURE_THRESHOLD:
        disclosure_required = True
        _raise_risk("medium")
        reasons.append(
            f"amount exceeds the {_DISCLOSURE_THRESHOLD} disclosure threshold — "
            f"large-transaction reporting required"
        )

    # 3. Currency / jurisdiction risk.
    if currency.upper() in _HIGH_RISK_CURRENCIES:
        _raise_risk("high")
        reasons.append(f"currency {currency.upper()} is a higher-risk jurisdiction")

    return {
        "flagged": flagged,
        "disclosure_required": disclosure_required,
        "risk": risk,
        "reasons": reasons,
        "amount": amount,
        "currency": currency,
    }


# ── registry ──────────────────────────────────────────────────────────────────
# server name -> {"capability": "tool.x", <tool_name>: callable}. Each server advertises
# exactly one capability (so capability discovery is a clean server<->capability map);
# the callables are the deterministic functions above.
TOOLS: dict[str, dict[str, Any]] = {
    "pii-scan": {"capability": "tool.pii", "scan": pii_scan},
    "compliance-lookup": {"capability": "tool.compliance", "lookup": compliance_lookup},
    "risk-score": {"capability": "tool.risk", "assess": risk_assess},
    "data-classify": {"capability": "tool.classify", "classify": classify},
    "fin-check": {"capability": "tool.fincheck", "screen": fin_check},
}

# capability -> server, and short-name -> capability, so AGT_LOCAL_TOOLS can list either
# "tool.pii" or just "pii". Defined here (above the helpers that use them) so module import
# order is correct.
TOOLS_BY_CAPABILITY = {entry["capability"]: server for server, entry in TOOLS.items()}
_CAP_BY_SHORT = {entry["capability"].split(".", 1)[-1]: entry["capability"]
                 for entry in TOOLS.values()}


def _enabled_capabilities() -> set[str] | None:
    """Parse ``AGT_LOCAL_TOOLS`` (CSV of capabilities or short names) into the set of enabled
    capability ids, or None when unset/empty (None = ALL tools, the back-compat default).

    Accepts full ids ("tool.pii") and short names ("pii"); unknown tokens are ignored so a
    typo can never silently enable a tool that doesn't exist. Read at CALL time so a test or
    a per-division launch can set it via the environment."""
    raw = (os.environ.get("AGT_LOCAL_TOOLS") or "").strip()
    if not raw:
        return None
    enabled: set[str] = set()
    for token in raw.split(","):
        t = token.strip()
        if not t:
            continue
        if t in TOOLS_BY_CAPABILITY:
            enabled.add(t)
        elif t in _CAP_BY_SHORT:
            enabled.add(_CAP_BY_SHORT[t])
    return enabled


def _enabled_servers() -> set[str]:
    """The set of local server names this division actually serves, after applying the
    ``AGT_LOCAL_TOOLS`` filter. Unset → every local server."""
    enabled_caps = _enabled_capabilities()
    if enabled_caps is None:
        return set(TOOLS)
    return {server for server, entry in TOOLS.items() if entry["capability"] in enabled_caps}


def capability_for(server: str) -> str | None:
    """Return the capability an ENABLED local server advertises, or None if the server is
    unknown or disabled for this division (so a non-serving division reports None)."""
    if server not in _enabled_servers():
        return None
    entry = TOOLS.get(server)
    return entry["capability"] if entry else None


def server_for_capability(cap: str) -> str | None:
    """Return the local server that serves ``cap`` (e.g. "tool.pii") IF this division serves
    it, else None. A division that doesn't serve the capability returns None — so its
    solve_with_tools knows it lacks the tool locally and will DELEGATE."""
    enabled = _enabled_servers()
    for server, entry in TOOLS.items():
        if entry["capability"] == cap and server in enabled:
            return server
    return None


async def local_caller(server_cfg: dict, tool: str, arguments: dict) -> Any:
    """Transport ``caller`` for ``tools.mcp.call_mcp_tool`` — dispatches an in-process
    local tool. Pure compute: NO network, NO filesystem.

    ``server_cfg`` is the merged mcp_servers entry; we key off ``server_cfg["name"]``.
    Unknown server or tool → ``McpToolError`` (so a misroute fails closed, consistent
    with the executor's other gate failures)."""
    server = server_cfg.get("name", "")
    entry = TOOLS.get(server)
    if entry is None:
        raise McpToolError(f"local tool server '{server}' is not registered")
    func = entry.get(tool)
    if not callable(func):
        raise McpToolError(f"local tool '{tool}' is not available on server '{server}'")
    try:
        # The registered tools are sync, pure-compute functions; call directly.
        return func(arguments)
    except (ValueError, ArithmeticError) as exc:
        # A tool-level error — a bad/oversized input (ValueError) or an arithmetic fault.
        # Wrap as McpToolError so the governed path surfaces ONE error type and stays
        # fail-closed instead of leaking a raw exception. SECURITY: the message never
        # contains tool INPUT (no raw PII), only the validation reason.
        raise McpToolError(f"local tool '{server}/{tool}' rejected arguments: {exc}") from exc


def local_server_configs() -> list[dict]:
    """Return the ``settings.mcp_servers`` entries for the ENABLED local tool servers.

    Only servers this division serves (per ``AGT_LOCAL_TOOLS``) are returned — this is the
    one place the filter propagates from, so it reaches both advertised_capabilities (gate-2
    registration is keyed off these) and the gateway. ``auth_mode: "service_rebac"`` is our
    semantic (service credential, no user token); the gateway's ``allowed_auth_methods`` is
    ``["bearer"]`` (a real gateway auth method) and ``require_tls`` is False with an empty
    ``url`` because the call never leaves the process."""
    enabled = _enabled_servers()
    configs: list[dict] = []
    for server, entry in TOOLS.items():
        if server not in enabled:
            continue
        tool_names = [k for k in entry if k != "capability"]
        configs.append({
            "name": server,
            "url": "",
            "allowed_auth_methods": ["bearer"],
            "require_tls": False,
            "auth_mode": "service_rebac",
            "capability": entry["capability"],
            "tools": tool_names,
        })
    return configs


def ensure_local_servers_registered() -> None:
    """Idempotently make the ENABLED local servers usable by the governed executor — in BOTH
    the settings list AND the executor's CACHED gateway.

    The gateway requires every server be in settings.mcp_servers (gate 2). Two states must be
    reconciled, and they are INDEPENDENT:

      (a) settings.mcp_servers is missing an enabled local server → append it.
      (b) the executor's CACHED gateway (``tools.mcp._server_cfg``, built once and reused) is
          missing an enabled local server even though settings now lists it. This happens when
          another test/suite monkeypatched settings.mcp_servers, the executor built+cached a
          gateway from THAT value, and pytest later reverted settings — leaving a warm gateway
          that predates our servers. The old code returned early in this case (names already in
          settings) and never reset the cache, so run_local_tool would resolve the stale
          gateway, not find the local server, and raise McpToolError ("server not configured").

    Reset the cache whenever EITHER hole exists, so the gateway rebuilds from the merged
    settings. FAILURE DIRECTION IS SAFE EITHER WAY: a stale gateway only ever causes a
    legitimate call to fail CLOSED (gate 2 rejects an unconfigured-looking server) — it can
    NEVER make an unconfigured server pass. This fix is purely about reliability (no spurious
    fail-closed for our own registered tools); it does not loosen any gate. Safe to call
    repeatedly; idempotent once the gateway is fresh."""
    import json

    from config import settings
    from tools import mcp as mcp_tools

    raw = (settings.mcp_servers or "").strip()
    existing: list[dict] = []
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                existing = parsed
        except json.JSONDecodeError:
            existing = []

    local_names = {c["name"] for c in local_server_configs()}
    existing_names = {s.get("name") for s in existing if isinstance(s, dict)}
    to_add = [c for c in local_server_configs() if c["name"] not in existing_names]

    # (a) Backfill any enabled local server missing from settings.mcp_servers.
    if to_add:
        settings.mcp_servers = json.dumps(existing + to_add)
        mcp_tools.reset_cache()
        return

    # (b) Settings already lists every enabled local server, but the cached gateway may predate
    #     them (warm cache built from a since-reverted settings value). If the cache is warm and
    #     missing ANY enabled local server, drop it so the next call rebuilds from current
    #     settings.
    cached_gateway = getattr(mcp_tools, "_gateway", None)
    if cached_gateway is not None:
        cached_names = set(getattr(mcp_tools, "_server_cfg", {}) or {})
        if not local_names.issubset(cached_names):
            mcp_tools.reset_cache()


async def run_local_tool(server: str, tool: str, arguments: dict, *,
                         agent_trust_score: float) -> Any:
    """Run a LOCAL governed tool end-to-end through ALL governance gates and execute it.

    Delegates to ``tools.mcp.call_mcp_tool`` with ``local_caller`` as the transport, so the
    policy default-deny, the McpAuthPolicy gateway, and the §4.2 no-credential boundary all
    apply before the tool runs. This is the function the agent (and the /a2a/tool endpoint)
    calls to actually execute a tool. Ensures the enabled local servers are registered first.

    ``agent_trust_score`` (required) is passed through to the mcp.call policy context: the
    signing peer's trust for /a2a/tool, LOCAL_AGENT_TRUST_SCORE for a local /solve."""
    from tools.mcp import call_mcp_tool

    ensure_local_servers_registered()
    return await call_mcp_tool(server, tool, arguments, agent_trust_score=agent_trust_score,
                               caller=local_caller)
