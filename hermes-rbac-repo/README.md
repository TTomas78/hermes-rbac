# hermes-rbac

Role-based access control (RBAC) with role inheritance for multi-user [Hermes Agent](https://github.com/NousResearch/hermes-agent) deployments.

One Hermes gateway serving multiple users (Discord, Telegram, WhatsApp, ...) means everyone shares the same tools, skills, and shell access by default. **hermes-rbac** adds a permission layer:

- **Message dispatch gating** (`pre_gateway_dispatch` hook): unauthorized users get an access-denied notice — the agent never sees their message.
- **Tool/skill gating** (`pre_tool_call` hook): blocks toolsets not allowed by the user's role, restricts `skill_view` to role-permitted skills, and protects sensitive paths (`.env`, `config.yaml`, `state.db`) unless the role has `bypass_sensitive_paths`.
- **Cross-platform identity linking**: one human with Discord + Telegram accounts maps to a single canonical identity with one role set and one memory bank.
- **Role inheritance**: roles can `extend` other roles; permissions resolve transitively.
- **Fail-closed by default**: broken config = no access (except `bootstrap_admins`, who always get in to fix it).
- **Audit log**: every gate decision lands in `audit.jsonl`.

## Requirements

- Hermes Agent with plugin support (see [plugins docs](https://hermes-agent.nousresearch.com/docs)).
- Python 3.11+.
- No external dependencies (stdlib + PyYAML, which Hermes already ships).

## Installation

```bash
git clone https://github.com/TTomas78/hermes-rbac ~/.hermes/plugins/hermes-rbac
cd ~/.hermes/plugins/hermes-rbac
cp roles.yaml.example roles.yaml
cp identities.yaml.example identities.yaml
```

Edit `roles.yaml`: set `bootstrap_admins` to your own `platform:user_id` (e.g. `discord:123456789`), then restart the Hermes gateway.

To find your user ID, just message the bot — the audit log records every attempt with its `platform:user_id` key.

## Configuration

### roles.yaml

```yaml
fail_closed: true

bootstrap_admins:
  - "discord:YOUR_USER_ID"     # always full access, even if config breaks

roles:
  admin:
    toolsets: ["*"]
    skills: ["*"]
    bypass_sensitive_paths: true

  dev:
    extends: [viewer]
    toolsets: [terminal, read_file, write_file, patch, search_files, mcp__github__*]
    skills: [test-driven-development, github-pr-workflow]

  viewer:
    toolsets: [web_search, web_extract, skill_view]
    skills: [youtube-content]

  guest:
    toolsets: []
    skills: []

users:
  "discord:YOUR_USER_ID": [admin]
  "telegram:SOME_ID": [viewer]
  # "*": [guest]              # uncomment for a default role for unknown users
```

- `toolsets` are Hermes tool names with glob support (`mcp__github__*`).
- `skills` are skill names (no glob except `"*"`).
- `fail_closed: true` (recommended): unknown users and broken configs deny everything. With `false`, config errors fall back to open access.
- Hot-reload: editing the file reloads it automatically (mtime-based); no gateway restart needed.

### identities.yaml

Groups multiple `platform:user_id` keys belonging to the same human under one canonical identity. Roles attach to the canonical key:

```yaml
persons:
  tomas:
    canonical: discord:111222333
    identities:
      - discord:111222333
      - telegram:444555666
```

## Usage

### Slash command (in chat)

- `/rbac whoami` — your identity, roles, and resolved permissions
- `/rbac roles` — list roles
- `/rbac user <platform:id>` — inspect a user (admin)

> **Note:** `whoami` currently can't see *who* is asking from a slash command (the Hermes slash-command framework doesn't pass sender context yet — see upstream PR [#91527](https://github.com/NousResearch/hermes-agent/pull/91527)). Until that lands, use the CLI below.

### CLI (admin, on the host)

```bash
hermes rbac roles                    # list roles with resolved permissions
hermes rbac users                    # list users and roles
hermes rbac user discord:123         # inspect one user's effective access
hermes rbac assign discord:123 dev   # grant a role
hermes rbac revoke discord:123 dev   # remove a role
hermes rbac reload                   # force reload from disk
hermes rbac audit -n 20              # last 20 gate decisions
hermes rbac identities               # list identity links
hermes rbac link-challenge discord:123        # start cross-platform link
hermes rbac link-confirm telegram:456 LINK-XXXXXX
hermes rbac unlink telegram:456
```

Role mutations are **CLI-only by design**: it prevents privilege self-escalation from the chat.

## Upstream PRs

This plugin works with current Hermes Agent. Two upstream PRs improve the integration (optional, backwards-compatible):

- [#90977](https://github.com/NousResearch/hermes-agent/pull/90977) — `{"action": "authorize"}` for `pre_gateway_dispatch`: lets the plugin act as the authorization layer (skip platform allowlist after authenticating the sender itself).
- [#91527](https://github.com/NousResearch/hermes-agent/pull/91527) — sender context (opt-in) for plugin slash commands: enables `/rbac whoami` to work from chat.

## Development

```bash
cd ~/.hermes/plugins/hermes-rbac
uv run --extra dev pytest tests/ -q     # 74 tests
```

## License

MIT — see [LICENSE](LICENSE).
