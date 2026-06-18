"""FR-3.6 Wave-3: recipient-bound, time-limited cross-division user assertion.

The cross-division user assertion is NOT the user's raw home token. The home
division forwards its already-VALIDATED identity claims (sub/email/email_verified/iss)
inside the DID-signed, replay-protected envelope, and Wave 3 makes that assertion
VERIFIABLE + NON-REPLAYABLE at the receiver by adding three independent bindings:

  1. RECIPIENT BINDING — ``aud`` = the TARGET division's DID; the receiver accepts only
     if ``aud`` == its OWN DID, so an assertion minted for B cannot be forwarded to C.
  2. EXPIRY — short ``exp`` (set by the sender); a passed/missing exp is rejected.
  3. ISSUER BINDING — ``iss`` bound to the SPECIFIC signing peer's DID (not the trusted
     SET), so a compromised-but-trusted peer can never assert another division's user.

These hermetic tests pin REAL behavior at both layers:
  * the sender's binding (mesh.peer_client._bind_user_assertion), and
  * the receiver's validation (auth.token_validator.validate_cross_division_assertion):
    accepted when aud==self + unexpired + valid signer-bound issuer; rejected when aud is
    ANOTHER division (recipient binding), when expired, and when the signer DID isn't the
    asserted issuer's bound peer (cross-issuer spoof) — all fail-closed.
"""
from __future__ import annotations

import time

import pytest

# This division (the receiver) — its DID is the audience the assertion must bind to.
SELF_DID = "did:mesh:self0000000000000000000000000000"
OTHER_DID = "did:mesh:other000000000000000000000000000"   # a different division's DID

ALPHA_ISS = "http://localhost:8402/realms/rag"   # the signing peer's bound issuer
GAMMA_ISS = "http://localhost:8302/realms/rag"   # a DIFFERENT trusted division's issuer


def _bound(
    *,
    aud=SELF_DID,
    iss=ALPHA_ISS,
    email="alice@example.com",
    verified=True,
    exp_delta=300,
    include_exp=True,
):
    """A receiver-shaped assertion: home claims + the sender's binding fields."""
    a = {"iss": iss, "email": email, "email_verified": verified, "sub": "abc", "aud": aud}
    if include_exp:
        a["exp"] = int(time.time()) + exp_delta
        a["iat"] = int(time.time())
        a["jti"] = "jti-1"
    return a


# ── Receiver: full recipient-bound validation ──────────────────────────────────

def test_accepts_when_aud_self_unexpired_valid_signer():
    from auth.token_validator import principal, validate_cross_division_assertion
    got = validate_cross_division_assertion(
        _bound(), expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
    )
    # Same namespaced principal the local path would derive for these claims.
    assert got == principal(
        {"iss": ALPHA_ISS, "email": "alice@example.com", "email_verified": True, "sub": "abc"}
    )
    assert got.startswith("alice@example.com|")


def test_rejects_when_aud_is_another_division():
    # RECIPIENT BINDING: an assertion the home division minted for OTHER_DID must not be
    # accepted by this division (whose DID is SELF_DID) — no cross-recipient replay.
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            _bound(aud=OTHER_DID), expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
        )


def test_rejects_when_aud_missing():
    from auth.token_validator import validate_cross_division_assertion
    a = _bound()
    a.pop("aud")
    with pytest.raises(ValueError):
        validate_cross_division_assertion(a, expected_issuer=ALPHA_ISS, expected_audience=SELF_DID)


def test_rejects_when_expired():
    # EXPIRY: an assertion whose exp has passed (beyond the skew allowance) is refused.
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            _bound(exp_delta=-3600), expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
        )


def test_rejects_when_exp_missing():
    # No unbounded-lifetime assertions: a missing exp is rejected outright.
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            _bound(include_exp=False), expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
        )


def test_rejects_when_exp_is_bool_or_zero():
    # `True` is an int subclass — must not be mistaken for a valid timestamp; 0 is invalid.
    from auth.token_validator import validate_cross_division_assertion
    a = _bound()
    a["exp"] = True
    with pytest.raises(ValueError):
        validate_cross_division_assertion(a, expected_issuer=ALPHA_ISS, expected_audience=SELF_DID)
    a["exp"] = 0
    with pytest.raises(ValueError):
        validate_cross_division_assertion(a, expected_issuer=ALPHA_ISS, expected_audience=SELF_DID)


def test_rejects_when_exp_is_non_finite():
    # NEVER-EXPIRING ASSERTION (High): float('inf')/float('nan') are floats, not bool, and
    # inf<=0 / nan<=0 are both False, so they slip past a naive `<= 0` guard; the expiry
    # comparison `now > inf` / `now > nan` is then always False → the assertion NEVER expires,
    # collapsing the short-exp bound the design depends on. The validator must reject any
    # non-finite exp (math.isfinite guard). Also covers the JSON `1e400` overflow, which
    # json.loads coerces to inf — so at the validator it presents as float('inf').
    import math

    from auth.token_validator import validate_cross_division_assertion
    for bad in (float("inf"), float("-inf"), float("nan")):
        a = _bound()
        a["exp"] = bad
        with pytest.raises(ValueError):
            validate_cross_division_assertion(
                a, expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
            )
    # The legitimate finite exp (e.g. 300s out) is still accepted — the guard is finite-only,
    # not float-rejecting.
    assert math.isfinite(_bound()["exp"])
    assert validate_cross_division_assertion(
        _bound(), expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
    ).startswith("alice@example.com|")


def test_a2a_json_edge_rejects_non_finite_numbers():
    # Belt-and-braces at the wire: /a2a/query parses the body with main._loads_finite, which
    # refuses the non-standard JSON tokens Infinity/-Infinity/NaN AND the overflowing literal
    # 1e400 (which the default json.loads silently turns into float('inf')). This stops an
    # inf/nan `exp` from ever entering the system, independent of the validator's finite guard.
    from api import main
    # A finite, well-formed body still parses.
    ok = main._loads_finite(b'{"exp": 1750000000, "q": "hi"}')
    assert ok["exp"] == 1750000000
    for bad_body in (
        b'{"exp": Infinity}',
        b'{"exp": -Infinity}',
        b'{"exp": NaN}',
        b'{"exp": 1e400}',                 # overflows to inf under default json.loads
        b'{"nested": {"exp": 1e400}}',     # caught anywhere in the document, not just top-level
    ):
        with pytest.raises(ValueError):
            main._loads_finite(bad_body)


def test_rejects_cross_issuer_spoof():
    # CROSS-ISSUER SPOOF (fail-closed): the signing peer's bound issuer is ALPHA, but the
    # assertion claims a GAMMA-issuer user. Even though aud + exp are valid and gamma is a
    # real division, binding iss to the SIGNER rejects it — no cross-division impersonation.
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            _bound(iss=GAMMA_ISS, email="ceo@example.com"),
            expected_issuer=ALPHA_ISS,            # the issuer bound to the signing peer
            expected_audience=SELF_DID,
        )


def test_fails_closed_without_bound_issuer():
    # A misconfigured trust-map entry (no issuer bound to the signer) must never fall back
    # to accepting any issuer.
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            _bound(), expected_issuer="", expected_audience=SELF_DID
        )


def test_fails_closed_without_audience():
    # If the receiver could not resolve its own DID, refuse rather than skip the binding.
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            _bound(), expected_issuer=ALPHA_ISS, expected_audience=""
        )


def test_rejects_unverified_email():
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            _bound(verified=False), expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
        )


def test_rejects_non_dict_assertion():
    # A raw string (e.g. a forwarded token) must not be accepted as an assertion.
    from auth.token_validator import validate_cross_division_assertion
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            "eyJhbGciOi...", expected_issuer=ALPHA_ISS, expected_audience=SELF_DID  # type: ignore[arg-type]
        )


def test_accepts_within_clock_skew():
    # An exp just barely passed (within the skew allowance) is still accepted, so small
    # inter-division clock drift doesn't reject legitimate assertions.
    from auth.token_validator import validate_cross_division_assertion
    got = validate_cross_division_assertion(
        _bound(exp_delta=-10), expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
    )
    assert got.startswith("alice@example.com|")


# ── Sender: the binding the home division applies before signing ────────────────

def test_sender_binds_aud_exp_jti_to_target():
    # mesh.peer_client._bind_user_assertion turns the home claims into a recipient-bound,
    # time-limited assertion: aud = the target peer's DID, plus iat/exp/jti.
    from mesh.peer_client import _USER_ASSERTION_TTL_SECONDS, _bind_user_assertion
    home = {"iss": ALPHA_ISS, "email": "alice@example.com", "email_verified": True, "sub": "abc"}
    before = int(time.time())
    out = _bind_user_assertion(home, audience=OTHER_DID)
    assert out["aud"] == OTHER_DID
    assert out["iss"] == ALPHA_ISS and out["email"] == "alice@example.com"
    assert isinstance(out["exp"], int) and out["exp"] >= before + _USER_ASSERTION_TTL_SECONDS - 2
    assert isinstance(out["iat"], int) and out["iat"] >= before - 2
    assert isinstance(out["jti"], str) and out["jti"]
    # The home claims object is not mutated in place.
    assert "aud" not in home


def test_sender_jti_is_unique_per_call():
    from mesh.peer_client import _bind_user_assertion
    home = {"iss": ALPHA_ISS, "email": "a@x", "email_verified": True, "sub": "s"}
    a = _bind_user_assertion(home, audience=OTHER_DID)
    b = _bind_user_assertion(home, audience=OTHER_DID)
    assert a["jti"] != b["jti"]


def test_sender_then_receiver_roundtrip():
    # End-to-end at the claims layer: bind to THIS division's DID, then validate it here.
    from auth.token_validator import validate_cross_division_assertion
    from mesh.peer_client import _bind_user_assertion
    home = {"iss": ALPHA_ISS, "email": "alice@example.com", "email_verified": True, "sub": "abc"}
    bound = _bind_user_assertion(home, audience=SELF_DID)
    got = validate_cross_division_assertion(
        bound, expected_issuer=ALPHA_ISS, expected_audience=SELF_DID
    )
    assert got.startswith("alice@example.com|")
    # Same assertion, presented to a DIFFERENT division, is rejected (recipient binding).
    with pytest.raises(ValueError):
        validate_cross_division_assertion(
            bound, expected_issuer=ALPHA_ISS, expected_audience=OTHER_DID
        )
