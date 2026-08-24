# Family / friends setup

**Scenario:** you run one Hermes bot for your household. You want full access, your sibling gets normal chat access, and a guest can only use read-only tools.

## roles.yaml

```yaml
roles:
  admin:
    tools: ["*"]
    skills: ["*"]
    sensitive_paths: true

  user:
    tools: ["read_*", "search_*", "web_*", "browser_*", "memory"]
    skills: ["*"]
    sensitive_paths: false

  guest:
    tools: ["web_search"]
    skills: []
    sensitive_paths: false
```

## identities.yaml

```yaml
persons:
  me:
    canonical: discord:111222333
    identities:
      - discord:111222333
      - telegram:444555666
    roles: [admin]

  sibling:
    canonical: telegram:777888999
    identities:
      - telegram:777888999
    roles: [user]

  guest-cousin:
    canonical: discord:555666777
    identities:
      - discord:555666777
    roles: [guest]
```

## What happens

| Message from | Resolved to | Role | Can run terminal? | Can read files? | Can web search? |
|---|---|---|---|---|---|
| You (Discord) | `discord:111222333` | admin | ✅ | ✅ | ✅ |
| You (Telegram) | `discord:111222333` (linked) | admin | ✅ | ✅ | ✅ |
| Sibling (Telegram) | `telegram:777888999` | user | ❌ | ✅ | ✅ |
| Cousin (Discord) | `discord:555666777` | guest | ❌ | ❌ | ✅ |
| Random stranger | unknown | *none* | ❌ (fail-closed) | ❌ | ❌ |

## Verify it works

1. Restart the gateway: `hermes gateway restart`
2. From your sibling's Telegram: `/rbac whoami` → should show role `user`
3. Have your sibling ask: *"run ls -la"* → the `terminal` tool gets denied (see `~/.hermes/plugins/hermes-rbac/audit.jsonl`)
4. From a stranger account: any message → silently denied, logged in `audit.jsonl`

## Linking your own accounts (OTP)

You're on Discord as admin and want your Telegram to be the same person:

```
# On Discord (or CLI):
hermes rbac link-challenge discord:111222333
# → LINK-A3F9K2 (valid 5 minutes)

# On Telegram:
hermes rbac link-confirm telegram:444555666 LINK-A3F9K2 --keep-memory a
# → linked; Telegram messages now resolve to discord:111222333
```

`--keep-memory a` keeps the Discord memory bank as canonical; the Telegram bank is archived (recoverable with `unlink`).
