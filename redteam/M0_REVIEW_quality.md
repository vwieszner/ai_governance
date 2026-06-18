# M0 Review — Code Quality (review gate, perspective 3/3)

Scope: `git diff 72585ee..HEAD`. Files: `scripts/onboard_division.py`, `infra/division-stack.template.yml`,
`infra/divisions/{alpha,beta,gamma}.yml`, `scripts/clusters.ps1`,
`agt-federated-rag/{config.py, mesh/peer_client.py, auth/openfga.py, api/main.py, conftest.py}`,
`agt-federated-rag/tests/test_{tenancy,onboarding,isolation}.py`.

Method: ran `ruff check` + `mypy --strict` (installed from the declared `dev` extras; neither was
present in the venv), ran the M0 unit suite, and compared `onboard_division.py` against the existing
`setup_agt.py` byte-for-byte.

**Verdict: 1 blocker (duplication → authz drift risk), the rest are should-fix / nits. M0 unit tests
are green. No correctness defect found in the new tenancy/onboarding logic itself.**

---

## Tooling results (facts)

| Gate | Result |
|---|---|
| `pytest tests/test_tenancy.py test_onboarding.py test_isolation.py` | **10 passed, 1 skipped** (the skip is `test_division_cannot_read_peer_store` — needs live stacks; see B-2). Green. |
| `ruff check` (M0 files) | **7 errors, all in `scripts/onboard_division.py`** — 6× E702 (semicolon statements), 1× F401 (`httpx` unused in `_wait`). 1 auto-fixable. |
| `mypy --strict` (M0 files) | New files add **15 errors** (`onboard_division.py` 12, `conftest.py` 3). The errors in `config.py`/`openfga.py`/`peer_client.py` are **pre-existing** (present at 72585ee — backend was already strict-dirty; verified), **not** an M0 regression. |

Note on framing: the repo is not mypy-strict-clean today, so "mypy not clean" is not an M0 blocker.
But the two **new greenfield files** should be clean, and they aren't — that's a should-fix below.

---

## BLOCKERS

### B-1 — `onboard_division.py` byte-duplicates provisioning logic from `setup_agt.py` → silent authz drift
**Why this is a blocker (not just "DRY"):** the OpenFGA `AUTH_MODEL` is **byte-identical** in both
files (`setup_agt.py:57-84` ≡ `scripts/onboard_division.py:48-75`, 1138 chars, verified). Both are
**actively-maintained provisioning paths** (the legacy 2-cluster setup and the new N-division
onboarding both run). A future change to the authorization model made in one file and not the other
yields **divisions whose ReBAC schema silently diverges** from the legacy clusters / from each other.
That is correctness-adjacent (authz semantics), which is what raises it past a style nit.

Confirmed byte-identical duplicates:
- `AUTH_MODEL` — `setup_agt.py:57-84` ≡ `onboard_division.py:48-75`
- ingest snippet — `_QDRANT_INGEST` `setup_agt.py:337-360` ≡ `_DIV_INGEST_SNIPPET` `onboard_division.py:366-389`
- `_load_root_env` — `setup_agt.py:91-100` ≡ `onboard_division.py:251-260`

Plus **near-identical** (structurally duplicated, parameter-level differences):
- `ensure_identity` — `setup_agt.py:126-149` vs `onboard_division.py:352-363`
- `kc_ensure_user` vs `_kc_ensure_user` — `setup_agt.py:249-268` vs `onboard_division.py:424-440`
- `kc_sub` vs `_kc_user_sub` — `setup_agt.py:271-279` vs `onboard_division.py:443-451`
- audience mapper: `kc_ensure_ui_client` vs `_kc_add_ui_audience`

**Fix — extract `scripts/_provisioning.py` that BOTH import.** Effort: ~1–2 h. Do it surgically:

- **Straight move (safe, identical today):** `AUTH_MODEL`, the ingest snippet, `_load_root_env`.
- **Move + retire the weaker variant:** `ensure_identity`. Host **onboard's hardened version** —
  it writes the Ed25519 private key via `os.open(..., 0o600)` atomically (`onboard_division.py:236-248`).
  `setup_agt.py`'s `write_text()` then `os.chmod()` (`setup_agt.py:144-148`) leaves a brief
  world-readable window; folding both onto the hardened path retires that gap.
- **DO NOT naively merge the Keycloak audience helpers — parameterize them.** `setup_agt.kc_ensure_ui_client`
  attaches **both** agent audiences (`agent-agt-a`, `agent-agt-b`) — that dual-audience mapper **is AUD-1**,
  which M1 is slated to delete. `onboard._kc_add_ui_audience` attaches a **single** division audience
  (the correct, post-AUD-1 shape). That difference is **load-bearing and security-relevant**; the shared
  helper must take the audience(s) as a parameter, not hard-code one behavior. `kc_ensure_user` is a clean
  parameterized move.

`setup_agt.py` is **not** being retired — IMPLEMENTATION_PLAN M1 deletes only the one function
`kc_ensure_ui_client`, so the two scripts coexist. Extraction is therefore worth it (it isn't coupling
a dying script to a new one).

---

## SHOULD-FIX

### S-1 — `_parse_simple_yaml` reinvents a YAML parser that's already an unavoidable dependency
`scripts/onboard_division.py:97-117`. The docstring says it "avoids a hard PyYAML dependency," but
**PyYAML is already a hard transitive dependency** of the core AGT stack — `agentmesh-platform`,
`agent-governance-toolkit`, `agent-sre`, `agent-os-kernel`, and langchain all require `pyyaml>=6.0`
(verified: `pip show pyyaml` → `Required-by: agent_governance_toolkit, agent_sre, agentmesh_platform, ...`).
It is guaranteed present in any environment the backend runs in. So the stated rationale doesn't hold.

The hand-rolled parser is also **silently lossy** on valid YAML the manifests could grow into: nested
keys, quoted values containing `:` or `#` (`#` inside a value is treated as a comment and truncated),
multi-line lists, `key:` with an empty value vs `key: []`. Today's flat manifests don't hit these, but
the next person who adds a nested field gets a wrong parse with no error.
**Fix:** `import yaml; data = yaml.safe_load(text)` and drop `_parse_simple_yaml` (keep `load_manifest`'s
validation). If a true zero-dep guarantee is genuinely required (it isn't here), keep the hand-roll but
fix the docstring to state the real reason and add a test for the `#`-in-value case.

### S-2 — `ruff check`: 7 errors in the new file (all trivially fixable)
`scripts/onboard_division.py`: E702 at lines 279, 303, 305, 334, 398, 500 (`a; b` one-liners — split
them), and F401 at 275 (`import httpx` inside `_wait` is unused — `_wait` only uses the passed-in
client `c`; remove the inner import, `provision` already imports httpx at 288). `ruff check --fix`
clears the F401; the E702s are a 2-minute manual split. Greenfield code should pass the gate the plan
itself mandates (`ruff check` clean).

### S-3 — `mypy --strict`: 15 new errors in the two new files
New greenfield files should be strict-clean. `onboard_division.py` (12): untyped `dict` generics
(`97,352,403,424,492` → `dict[str, ...]`), untyped params on the `httpx`-client helpers
(`_wait` 274, `_kc_add_ui_audience` 403, `_kc_ensure_user` 424, `_kc_user_sub` 443, `_seed_division_tuples`
454 — annotate `c: httpx.AsyncClient`), a `no-any-return` at 451 (`json.loads(...)["sub"]` → cast/str()),
and an unused `type: ignore` at 354. `conftest.py` (3): `make_settings`/`_make` need return + param
annotations, and `_env_file=None` (49) trips `call-arg` — pydantic-settings accepts it at runtime
(tests pass), but mypy needs `# type: ignore[call-arg]` with a one-line note, or use the documented
`model_config`/`_env_file` typing. The pre-existing strict-dirt elsewhere is separate, repo-wide debt
(out of M0 scope).

### S-4 — NFR-10 is claimed in M0's header but neither proven nor satisfied
M0's milestone line claims NFR-10, but: (a) the traceability table maps NFR-10 to `test_portability`
in **M7**, not M0; (b) the PRD itself flags *"Today: hostnames/ports hardcoded to localhost"*; and
(c) `render_agent_env` (`onboard_division.py:181-222`) hardcodes `http://localhost:{port}` for every
endpoint (Keycloak issuer/JWKS/token, Qdrant, OpenFGA, Temporal, agent URL, approval base, CORS).
This isn't wrong for dev, but the M0 header over-claims. **Fix:** drop NFR-10 from M0's "Proves" set
(it's an M7 deliverable), or add a `host`/`domain` manifest field threaded into `render_agent_env` so
endpoints are configurable now. Recommend the former — keep M0 honest, leave portability to M7.
(Same applies softer to NFR-8: M0's `test_onboard_no_source_edit` covers the "no manual multi-file
edits" half; the full IaC proof is `test_iac` in M7. Acceptable, but the header reads stronger than
the tests deliver.)

---

## TEST ADEQUACY vs the M0 traceability row

Requirement text (PRODUCT_REQUIREMENTS.md) → does M0 actually prove it?

| Req | Text (abridged) | M0 proof | Adequate? |
|---|---|---|---|
| **FR-1.1** | N independent divisions (N≥2) from one codebase + parameterized config | `test_three_divisions_from_config` (≥3 manifests, unique ids/projects, globally-distinct ports) | **Yes** — strong; the global-port-collision assert is the right discriminator. |
| **FR-1.2** | Isolated data plane per division (own KB, own approval state, own authz store) | `test_division_cannot_read_peer_store` | **Conditionally** — see B-2: the test **skips** without live stacks. |
| **FR-1.3** | Repeatable parameterized onboarding without editing source | `test_onboard_no_source_edit` (hashes all sources, runs dry-run onboard, asserts no source mutated + artifact landed under `infra/generated/`) | **Yes** — good design; the source-hash snapshot is a genuine proof. |
| **FR-1.4** | Stable division id carried through tokens, authz tuples, audit, inter-agent msgs | `test_division_id_threaded_into_a2a_envelope` (drives real `peer_client.call_peer_agent`, asserts signed `source_division`); `config.py` threads it into OpenFGA audit + `/a2a/query`; default-to-cluster_id back-compat tested | **Partly** — A2A envelope + config contract proven. The **OpenFGA audit** (`openfga.py`) and **`/a2a/query` attribution** (`main.py`) threading is **not** asserted by any test — it's only verified by reading the diff. A small unit asserting the audit record carries `division_id` would close FR-1.4. |
| **NFR-2** | Blast radius: no shared point whose loss crosses a boundary; A can't read B's store | `test_division_cannot_read_peer_store` (store-not-found + cross-credential-rejected + distinct endpoints) | **Skipped by default** — see B-2. The kill-B half is an e2e (out of M0). |
| **NFR-8** | IaC standup, no manual multi-file edits | partial via `test_onboard_no_source_edit` | Partial (full proof = `test_iac`, M7). Acceptable; header over-reads. See S-4. |
| **NFR-10** | Configurable, not localhost-bound | none in M0; violated by `render_agent_env` | **Not proven, not satisfied.** See S-4. |

### B-2 (test-adequacy blocker on coverage, not code) — the discriminating isolation test never runs in CI
`tests/test_isolation.py::test_division_cannot_read_peer_store` is **the** test that makes tenancy
"real rather than a `division_id` label on shared infra" (its own docstring says so), and it proves
both FR-1.2 and NFR-2. But it `pytest.skip`s unless alpha+beta OpenFGA stacks are already running
(`test_isolation.py:23-24, 40-41`). In the unit/CI run it skipped (confirmed: "1 skipped"). **So the
headline M0 isolation guarantee is currently unproven by any test that runs by default.** The plan's
own "done" bar requires the milestone's tests to pass — a test that always skips doesn't pass, it
abstains.

**Fix (pick one):**
- **Best:** add a CI job (or a `@pytest.mark.integration` lane) that runs `onboard_division.py` for
  alpha+beta against ephemeral compose stacks, then runs this test — so the proof executes somewhere
  deterministic, not only on a dev's machine that happens to have stacks up.
- **Minimum:** keep the skip for the unit lane but add a *hermetic* unit that proves the isolation
  **mechanism** without docker — e.g. assert each division's `render_agent_env` points at a distinct
  `OPENFGA_API_URL` + distinct `OPENFGA_API_TOKEN`, and that `derive_ports` guarantees no two
  divisions share an OpenFGA port (some of this is in `test_onboarding`, but not framed as the
  isolation invariant). This proves the *configuration* isolation invariant in CI; the live store
  check stays as the integration confirmation.

I rate this a blocker on the **requirement coverage** (NFR-2/FR-1.2 are the M0 headline and the e2e
SC-12 anchor), not on the production code — the code is correct; the proof just doesn't run.

---

## NITS

- `scripts/clusters.ps1:40-41` parses `division_id`/`port_base` from manifests with regex. Fine and
  appropriately lightweight for PowerShell (no YAML dep there) — consistent with keeping the manifest
  format flat. No change needed; just flagging that the manifest format is now parsed in **three**
  places (PS regex, Python `_parse_simple_yaml`, and any future PyYAML switch) — another reason to keep
  the format dead-simple (S-1) so the three stay in agreement.
- `onboard_division.py:46` `SEED_USER_PASSWORD` default `"Rag-User-2026!"` is a hardcoded default
  (overridable via `RAG_SEED_PASSWORD`). Matches `setup_agt.py:44` — demo seed users, acceptable for
  M0, but worth a note when M1 does real role/user lifecycle (don't let a seed default leak into a
  non-demo division).
- `config.py` adds `residency_mode`/`require_mtls` now "threaded for M6/M7." They're inert in M0
  (only `test_residency_and_transport_defaults` asserts the defaults). Fine as forward-threading; just
  confirm M6/M7 actually read them so they don't become decorative config (the plan says they will).

---

## What's good (so the signal is balanced)
- `test_onboard_no_source_edit`'s source-hash snapshot is a genuinely good way to prove "no source
  edits" — better than asserting on a file list.
- `test_division_id_threaded_into_a2a_envelope` drives the **real** `call_peer_agent` code path with
  surgical monkeypatching rather than re-implementing the payload — the right way to test threading.
- `_write_secret` (`os.open(O_CREAT, 0o600)`) is the correct atomic-mode pattern and is an improvement
  over the legacy `write_text`+`chmod`; B-1 should propagate it, not lose it.
- `division-stack.template.yml` binds every published port to `127.0.0.1` and namespaces
  container_name/volumes/network per compose project — clean physical-isolation scaffolding.
