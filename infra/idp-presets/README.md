# IdP presets — connect the bundled Keycloak to a corporate identity system

The agent never manages users — it validates **OIDC tokens** against a configured issuer.
The bundled Keycloak is the universal adapter: point it at the customer's identity system
once, and the agent's token contract is unchanged. Three supported patterns, each a config
import (no code):

| Customer has… | Pattern | Preset file |
|---|---|---|
| On-prem Active Directory / LDAP | **User federation** — Keycloak verifies credentials against AD; users stay in AD | `ldap-ad-user-federation.json` |
| Entra ID (Azure AD) | **Identity brokering** — "Login" redirects to Entra (incl. MFA), returns to us | `oidc-broker-entra.json` |
| Okta / Auth0 / any OIDC | **Identity brokering** — same, against their OIDC IdP | `oidc-broker-okta.json` |
| (any of the above) **+ group-based access** | **Groups mapper** — emit the `groups` claim so [group grants](../../TEMPLATE_TASKS.md) resolve | `groups-mapper.json` |

You can also skip Keycloak entirely and point the agent **directly** at the customer IdP
(`OIDC_ISSUER` + the `PRINCIPAL_CLAIM`/`REQUIRE_VERIFIED_PRINCIPAL`/`GROUPS_CLAIM` config) —
the brokering presets are the no-code path when you want Keycloak to normalise everything.

## How to apply (admin REST API)

Each `*.json` is a Keycloak admin-API payload with `<<PLACEHOLDERS>>`. Fill the placeholders,
get an admin token, and POST it to the division's Keycloak realm. Example for the LDAP preset:

```bash
KC=http://localhost:9002           # division's Keycloak
REALM=rag
ADMIN_TOKEN=$(curl -s -d grant_type=password -d client_id=admin-cli \
  -d username=admin -d "password=$KC_ADMIN_PW" \
  "$KC/realms/master/protocol/openid-connect/token" | jq -r .access_token)

# User federation (LDAP/AD) — a realm "components" entry:
curl -s -X POST "$KC/admin/realms/$REALM/components" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d @ldap-ad-user-federation.json

# OIDC broker (Entra/Okta) — a realm "identity-provider/instances" entry:
curl -s -X POST "$KC/admin/realms/$REALM/identity-provider/instances" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d @oidc-broker-entra.json

# Groups claim mapper on the rag-ui client (lets group grants work) — see groups-mapper.json
# for the exact client-protocol-mappers endpoint + the agent-side GROUPS_CLAIM=groups default.
```

## Matching agent-side config

After importing a preset, set the agent's claim mapping to match the token the customer's
IdP actually emits (defaults shown; all in `agt-federated-rag/config.py`):

| Setting | Keycloak | Entra ID | Okta |
|---|---|---|---|
| `PRINCIPAL_CLAIM` | `email` | `preferred_username` (or `email`) | `email` |
| `REQUIRE_VERIFIED_PRINCIPAL` | `true` | `false` (Entra omits `email_verified`) | `true` |
| `GROUPS_CLAIM` | `groups` | `groups` (needs an Entra optional claim) | `groups` |

> Note: tokens the agent validates are still issued by **the division's Keycloak** in the
> federation/broker patterns, so `OIDC_ISSUER` stays the Keycloak realm. Only when pointing
> the agent **directly** at the customer IdP do you change `OIDC_ISSUER`/`OIDC_JWKS_URI`.
