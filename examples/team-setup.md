# Work team setup

**Scenario:** a small team shares one Hermes gateway on a company Discord. Devs get code tools, viewers get read-only, and one admin controls everything.

## roles.yaml (with inheritance)

```yaml
roles:
  viewer:
    tools: ["read_*", "web_search"]
    skills: []
    sensitive_paths: false

  dev:
    extends: viewer              # inherits read_* + web_search
    tools: ["write_*", "patch", "terminal", "git"]
    skills: ["software-development/*"]

  admin:
    tools: ["*"]
    skills: ["*"]
    sensitive_paths: true        # can read .env, config.yaml, etc.
```

## identities.yaml

```yaml
persons:
  alice:
    canonical: discord:100001
    identities: [discord:100001, telegram:200001]
    roles: [admin]

  bob:
    canonical: discord:100002
    identities: [discord:100002]
    roles: [dev]

  carol:
    canonical: discord:100003
    identities: [discord:100003]
    roles: [viewer]
```

## What inheritance does

`dev extends viewer` means Bob's effective tool allowlist is:

```
viewer.tools + dev.tools = ["read_*", "web_search", "write_*", "patch", "terminal", "git"]
```

Change `viewer` and every role extending it updates automatically. Inheritance is recursive (`admin` could extend `dev` too) with cycle detection.

## Testing permissions

```
# Bob (dev) asks to run a test suite:
"run pytest on the repo"          → terminal allowed ✅

# Carol (viewer) tries the same:
"run pytest on the repo"          → terminal denied ❌, logged to audit.jsonl

# Carol reads a file:
"summarize README.md"             → read_file allowed ✅

# Bob reads .env:
"what's in .env"                  → denied ❌ (sensitive_paths: false on dev)
```

## Audit trail

Every gate decision lands in `~/.hermes/plugins/hermes-rbac/audit.jsonl`:

```json
{"ts": "2026-08-24T12:00:00Z", "event": "deny", "user": "discord:100003",
 "reason": "role=viewer tool=terminal not_in_allowlist"}
{"ts": "2026-08-24T12:01:00Z", "event": "allow", "user": "discord:100002",
 "roles": ["dev"], "tool": "terminal"}
```

Grep it for incident review: `jq 'select(.event=="deny")' audit.jsonl`
