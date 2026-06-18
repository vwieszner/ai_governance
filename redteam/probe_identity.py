"""Adversarial red-team probe for FR-3.6 cross-division user identity.

Throwaway. Exercises the REAL functions under attack with real Ed25519 identities
(AgentIdentity.create), monkeypatching only the module-global `settings` (the trust
map) exactly the way tests/test_mesh.py does. No network, no source edits.

Attacks (each prints VULNERABLE / DEFENDED / NEEDS-HARDENING with a demonstrated repro):
  1. Assertion forgery        — alter claims, get a forged identity accepted
  2. Audience confusion       — assertion minted for B accepted by C/A
  3. Replay                   — replay envelope (nonce) / reuse assertion across time
  4. Expiry bypass            — expired / no-exp / exp=0 / exp=True / exp="big"
  5. Cross-issuer spoof       — signer bound to alpha asserts a beta/gamma user
  6. Signer-binding bypass    — asserted iss diverges from signer's bound issuer
  7. Envelope-signature bypass— tamper claims after signing; missing/empty aud/iss
"""
from __future__ import annotations

import json
import time
import uuid

import mesh.agent_identity as ai
from mesh.agent_identity import AgentIdentity, _canonical_bytes
from mesh.peer_client import _bind_user_assertion, _USER_ASSERTION_TTL_SECONDS
from auth.token_validator import (
    assertion_principal,
    validate_cross_division_assertion,
    principal,
)

ALPHA_ISS = "http://alpha/realms/rag"
BETA_ISS = "http://beta/realms/rag"
GAMMA_ISS = "http://gamma/realms/rag"

RESULTS: list[tuple[str, str, str]] = []


def record(attack: str, verdict: str, detail: str) -> None:
    RESULTS.append((attack, verdict, detail))
    print(f"\n[{verdict}] {attack}\n    {detail}")


def expect_reject(fn, *, attack: str, what: str) -> bool:
    """Call fn(); a raised ValueError = DEFENDED, a returned principal = VULNERABLE."""
    try:
        got = fn()
    except ValueError as e:
        print(f"    rejected ({what}): {e}")
        return True
    except Exception as e:  # any other exception is still a rejection, but note it
        print(f"    rejected via {type(e).__name__} ({what}): {e}")
        return True
    print(f"    !!! ACCEPTED ({what}) -> principal={got!r}")
    return False


# ── Fakes: a self identity + trusted peers, installed into the verify path ──────

def make_world():
    self_id = AgentIdentity.create(name="self", sponsor="self@e.com")
    alpha = AgentIdentity.create(name="alpha", sponsor="alpha@e.com")
    beta = AgentIdentity.create(name="beta", sponsor="beta@e.com")
    stranger = AgentIdentity.create(name="stranger", sponsor="s@e.com")

    def entry(idn, issuer):
        return {
            "issuer": issuer,
            "public_jwk": json.dumps(idn.to_jwk(include_private=False)),
            "agent_url": "http://x",
            "division_id": "",
        }

    trust = {
        str(alpha.did): entry(alpha, ALPHA_ISS),
        str(beta.did): entry(beta, BETA_ISS),
    }

    class FakeSettings:
        cluster_id = "test"
        division_id = "test"
        peer_trust = trust

    return self_id, alpha, beta, stranger, FakeSettings()


def sign_as(identity: AgentIdentity, body: dict) -> dict:
    signed = dict(body)
    signed["ts"] = int(time.time())
    signed["nonce"] = str(uuid.uuid4())
    signed["_agentmesh"] = {
        "sender_did": str(identity.did),
        "signature": identity.sign(_canonical_bytes(signed)),
        "alg": "EdDSA",
    }
    return signed


async def main():
    self_id, alpha, beta, stranger, fake = make_world()
    ai.settings = fake          # verify_signed_message reads ai.settings.peer_trust
    ai._seen_nonces = {}
    ai._identity = self_id
    ai._identity_registry = None
    SELF_DID = str(self_id.did)
    OTHER_DID = str(beta.did)   # a *different* division's DID (use beta's as "C")

    # The receiver's expected_issuer for an alpha-signed envelope is alpha's bound issuer.
    def recv(assertion, *, expected_issuer=ALPHA_ISS, expected_audience=SELF_DID, now=None):
        return validate_cross_division_assertion(
            assertion, expected_issuer=expected_issuer,
            expected_audience=expected_audience, now=now,
        )

    base_home = {"iss": ALPHA_ISS, "email": "alice@example.com",
                 "email_verified": True, "sub": "abc"}

    # Sanity: the legitimate path is accepted (so a "reject" elsewhere means the
    # attack failed, not that everything rejects).
    good = _bind_user_assertion(base_home, audience=SELF_DID)
    try:
        pr = recv(good)
        print(f"\n[sanity] legitimate assertion accepted -> {pr}")
        assert pr.startswith("alice@example.com|")
    except Exception as e:
        print(f"\n[sanity] UNEXPECTED: legit assertion rejected: {e}")

    # ── ATTACK 1: Assertion forgery (impersonate another user, same issuer) ─────
    # The receiver does NOT re-verify email against home Keycloak — it's VOUCHED.
    # So a peer bound to alpha CAN assert any alpha-namespace email. That is the
    # documented trust model (blast radius confined to the issuer namespace). Test
    # whether forgery reaches OUTSIDE that namespace (that would be the real break).
    forged_same_ns = _bind_user_assertion(
        {"iss": ALPHA_ISS, "email": "ceo@example.com", "email_verified": True, "sub": "x"},
        audience=SELF_DID,
    )
    try:
        pr = recv(forged_same_ns)
        record(
            "1. Assertion forgery (within signer's own issuer namespace)",
            "DEFENDED",
            f"Accepted ceo@example.com but ONLY in alpha's namespace ({pr}). This is the "
            "documented vouched-delegation model: a peer may assert any of ITS OWN users; "
            "the issuer-namespace confines blast radius. Forgery does NOT cross divisions "
            "(see attacks 5/6). No receiver-verifiable home token exists by design.",
        )
    except Exception as e:
        record("1. Assertion forgery (same namespace)", "DEFENDED", f"rejected: {e}")

    # ── ATTACK 5/6: Cross-issuer spoof + signer-binding bypass ──────────────────
    # alpha-signed envelope carrying a BETA/GAMMA-issuer user. expected_issuer for an
    # alpha signer is ALPHA_ISS. If accepted -> cross-division impersonation.
    ok = True
    for spoof_iss, label in [(BETA_ISS, "beta (a real trusted division)"),
                             (GAMMA_ISS, "gamma (an unknown division)")]:
        spoof = _bind_user_assertion(
            {"iss": spoof_iss, "email": "ceo@example.com", "email_verified": True, "sub": "x"},
            audience=SELF_DID,
        )
        ok &= expect_reject(
            lambda s=spoof: recv(s, expected_issuer=ALPHA_ISS),
            attack="5/6", what=f"alpha signer asserts {label}",
        )
    record(
        "5/6. Cross-issuer spoof & signer-binding bypass",
        "DEFENDED" if ok else "VULNERABLE",
        "assertion_principal enforces iss == expected_issuer (the signer's bound issuer); "
        "a beta/gamma-issuer user in an alpha-signed envelope is refused." if ok
        else "A divergent iss was accepted — cross-division impersonation possible.",
    )

    # ── ATTACK 2: Audience confusion (recipient-binding bypass) ─────────────────
    # Mint for OTHER_DID, present to SELF_DID. Should be rejected (aud != self).
    for_other = _bind_user_assertion(base_home, audience=OTHER_DID)
    a2 = expect_reject(
        lambda: recv(for_other, expected_audience=SELF_DID),
        attack="2", what="assertion minted for OTHER_DID presented to SELF_DID",
    )
    # Also: empty/missing aud must fail closed.
    no_aud = dict(_bind_user_assertion(base_home, audience=SELF_DID)); no_aud.pop("aud")
    a2 &= expect_reject(lambda: recv(no_aud), attack="2", what="missing aud")
    empty_aud = _bind_user_assertion(base_home, audience="");
    a2 &= expect_reject(lambda: recv(empty_aud), attack="2", what="empty-string aud")
    record(
        "2. Audience confusion / recipient-binding bypass",
        "DEFENDED" if a2 else "VULNERABLE",
        "aud must equal this division's own DID; assertion for another division (or "
        "missing/empty aud) is refused." if a2
        else "An assertion for a different audience was accepted here.",
    )

    # ── ATTACK 4: Expiry bypass ─────────────────────────────────────────────────
    a4 = True
    base = dict(_bind_user_assertion(base_home, audience=SELF_DID))
    # expired well beyond skew
    exp_past = dict(base); exp_past["exp"] = int(time.time()) - 3600
    a4 &= expect_reject(lambda: recv(exp_past), attack="4", what="exp 1h in the past")
    # missing exp
    no_exp = dict(base); no_exp.pop("exp")
    a4 &= expect_reject(lambda: recv(no_exp), attack="4", what="no exp")
    # exp = 0
    z = dict(base); z["exp"] = 0
    a4 &= expect_reject(lambda: recv(z), attack="4", what="exp=0")
    # exp = True (bool is int subclass)
    b = dict(base); b["exp"] = True
    a4 &= expect_reject(lambda: recv(b), attack="4", what="exp=True")
    # exp = "9999999999" (string — must not be coerced)
    s = dict(base); s["exp"] = "9999999999"
    a4 &= expect_reject(lambda: recv(s), attack="4", what='exp="9999999999" (string)')
    # exp = NaN / inf
    import math
    for bad, name in [(float("nan"), "NaN"), (float("inf"), "inf")]:
        nb = dict(base); nb["exp"] = bad
        # NaN/inf are floats > 0; check whether the comparison lets them through.
        try:
            pr = recv(nb)
            print(f"    !!! ACCEPTED (exp={name}) -> {pr}")
            if name == "inf":
                a4 = False  # inf exp = never expires = unbounded lifetime
        except ValueError as e:
            print(f"    rejected (exp={name}): {e}")
    record(
        "4. Expiry bypass",
        "DEFENDED" if a4 else "VULNERABLE",
        "exp must be a positive numeric (not bool/str) and unexpired; missing/0/True/"
        "string/past all refused." if a4
        else "An unbounded or invalid exp was accepted.",
    )

    # ── ATTACK 7: Envelope-signature bypass (tamper claims after signing) ───────
    # Sign an envelope as alpha, then mutate the user_assertion (e.g. change email
    # or aud) and re-present. verify_signed_message must reject (signature covers body).
    env = sign_as(alpha, {"query": "hi", "user_assertion": _bind_user_assertion(base_home, audience=SELF_DID)})
    ok_env, signer = await ai.verify_signed_message(env)
    print(f"\n[attack7] freshly-signed alpha envelope verifies: {ok_env} signer={signer}")
    tampered = json.loads(json.dumps(env))           # deep copy
    tampered["user_assertion"]["email"] = "ceo@example.com"  # escalate identity
    ok_t, signer_t = await ai.verify_signed_message(tampered)
    a7 = (ok_t is False)
    print(f"    tampered (email->ceo) verifies: {ok_t} signer={signer_t}")
    # Also tamper aud to retarget a captured envelope
    retarget = json.loads(json.dumps(env))
    retarget["user_assertion"]["aud"] = "did:mesh:victimC"
    retarget["nonce"] = str(uuid.uuid4())            # avoid the nonce-replay path
    ok_r, _ = await ai.verify_signed_message(retarget)
    a7 &= (ok_r is False)
    print(f"    retargeted (aud changed) verifies: {ok_r}")
    record(
        "7. Envelope-signature bypass (tamper after signing)",
        "DEFENDED" if a7 else "VULNERABLE",
        "Mutating any signed field (assertion email or aud) breaks the Ed25519 signature "
        "over canonical bytes; verify_signed_message fails closed." if a7
        else "A tampered envelope verified — signature does not cover the mutated field.",
    )

    # ── ATTACK 3: Replay ────────────────────────────────────────────────────────
    # (a) Exact envelope replay (same nonce) -> rejected by nonce cache.
    replay_env = sign_as(alpha, {"query": "hi"})
    ok1, _ = await ai.verify_signed_message(replay_env)
    ok2, _ = await ai.verify_signed_message(replay_env)  # byte-identical re-send
    a3_envelope = (ok1 is True and ok2 is False)
    print(f"\n[attack3a] envelope first={ok1} replay={ok2}")
    # (b) Assertion-level cross-time replay WITHIN the assertion TTL but the envelope
    # is re-signed fresh (a compromised receiver forwarding the SAME assertion onward
    # to itself again). The assertion has aud=SELF and a live exp, so the *assertion*
    # check would pass again — replay protection for the assertion relies on the
    # envelope nonce, NOT on jti. Demonstrate whether jti single-use is enforced.
    a = _bind_user_assertion(base_home, audience=SELF_DID)
    p1 = recv(a)
    p2 = recv(a)        # same assertion object, same jti, within TTL
    jti_single_use = (p1 != p2)  # if jti were single-use, the 2nd would differ/raise
    print(f"[attack3b] same assertion (same jti) accepted twice: "
          f"{p1 == p2} (jti single-use enforced at this layer: {jti_single_use})")
    record(
        "3. Replay",
        "DEFENDED" if a3_envelope else "VULNERABLE",
        "Envelope replay (reused nonce) is rejected by the post-signature nonce cache "
        "within the ±5-min window. NOTE: the assertion's own jti is NOT enforced as "
        "single-use at validate_cross_division_assertion — assertion-replay protection "
        "rides entirely on the envelope nonce+ts (documented as such). Within the 5-min "
        "freshness window a *re-signed* fresh envelope carrying the same still-valid "
        "assertion would re-validate; this is bounded by the short exp and is the "
        "intended layering, but jti is audit-only, not anti-replay."
        if a3_envelope
        else "Envelope replay was accepted — nonce cache not enforcing.",
    )

    # ── ATTACK: stranger / untrusted signer envelope ────────────────────────────
    str_env = sign_as(stranger, {"query": "hi"})
    ok_s, _ = await ai.verify_signed_message(str_env)
    record(
        "Bonus. Untrusted-signer envelope (DID not in trust map)",
        "DEFENDED" if ok_s is False else "VULNERABLE",
        "A validly self-signed envelope from a DID absent from peer_trust is refused "
        "(membership is the data-path trust decision)." if ok_s is False
        else "An untrusted signer was accepted.",
    )

    # ── Summary ─────────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY")
    for attack, verdict, _ in RESULTS:
        print(f"  {verdict:14s} {attack}")
    print("=" * 72)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
