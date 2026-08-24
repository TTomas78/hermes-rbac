"""Tests E2E del hook pre_tool_call (issues #4-#6).

Criterio de done: toolset bloqueado, skill no permitido bloqueado,
rutas sensibles bloqueadas sin bypass; contexto sin usuario = system full.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load(name: str):
    full = f"hermes_rbac_{name}"
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, PLUGIN_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


spec = importlib.util.spec_from_file_location("hermes_rbac_plugin", PLUGIN_DIR / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
sys.modules["hermes_rbac_plugin"] = plugin
spec.loader.exec_module(plugin)

# IMPORTANTE: usar el registry que cargo el plugin (__init__ lo carga con
# su propio loader por el guion del directorio). Cargarlo de nuevo aca
# crearia una instancia distinta con state _sessions separado.
registry = plugin.registry
resolver_mod = plugin.resolver if hasattr(plugin, "resolver") else _load("resolver")
audit_mod = plugin.audit if hasattr(plugin, "audit") else _load("audit")

CONFIG = {
    "fail_closed": True,
    "roles": {
        "viewer": {"toolsets": ["web_search", "web_extract", "skill_view"], "skills": ["youtube-content"]},
        "dev": {
            "extends": ["viewer"],
            "toolsets": ["terminal", "read_file", "write_file", "patch", "search_files", "web_search", "web_extract", "skill_view", "mcp__github__*"],
            "skills": ["test-driven-development", "youtube-content"],
        },
        "admin": {
            "toolsets": ["*"], "skills": ["*"], "bypass_sensitive_paths": True,
        },
    },
    "users": {
        "discord:view1": ["viewer"],
        "discord:dev1": ["dev"],
        "discord:admin1": ["admin"],
    },
}

SESSION = "discord:chat123:thread1"


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    cfg = tmp_path / "roles.yaml"
    cfg.write_text(yaml.safe_dump(CONFIG), encoding="utf-8")
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(plugin, "_resolver", resolver_mod.RoleResolver(config_path=cfg))
    monkeypatch.setattr(plugin, "_audit", audit_mod.AuditLog(path=audit_path))
    registry.clear()
    yield audit_path
    registry.clear()


def as_user(user_key):
    registry.register_session(SESSION, user_key)


class TestToolsetGate:
    def test_tool_permitida_pasa(self, setup):
        as_user("discord:view1")
        assert plugin._pre_tool_call(tool_name="web_search", args={"query": "x"},
                                     session_id=SESSION) is None

    def test_tool_bloqueada(self, setup):
        as_user("discord:view1")
        out = plugin._pre_tool_call(tool_name="terminal",
                                    args={"command": "ls"}, session_id=SESSION)
        assert out["action"] == "block"
        assert "terminal" in out["message"]
        entries = [json.loads(l) for l in setup.read_text().splitlines()]
        assert entries[-1]["decision"] == "block"
        assert entries[-1]["tool"] == "terminal"

    def test_glob_mcp(self, setup):
        as_user("discord:dev1")
        assert plugin._pre_tool_call(tool_name="mcp__github__create_issue",
                                     args={}, session_id=SESSION) is None
        out = plugin._pre_tool_call(tool_name="mcp__notion__search",
                                    args={"path": "/tmp/x"}, session_id=SESSION)
        assert out["action"] == "block"

    def test_admin_wildcard(self, setup):
        as_user("discord:admin1")
        assert plugin._pre_tool_call(tool_name="terminal",
                                     args={"command": "rm -rf /tmp/x"},
                                     session_id=SESSION) is None


class TestSkillGate:
    def test_skill_permitido(self, setup):
        as_user("discord:dev1")
        assert plugin._pre_tool_call(tool_name="skill_view",
                                     args={"name": "test-driven-development"},
                                     session_id=SESSION) is None

    def test_skill_bloqueado(self, setup):
        as_user("discord:dev1")
        out = plugin._pre_tool_call(tool_name="skill_view",
                                    args={"name": "godmode"}, session_id=SESSION)
        assert out["action"] == "block"
        assert "godmode" in out["message"]

    def test_skill_view_hereda_de_viewer(self, setup):
        as_user("discord:view1")
        assert plugin._pre_tool_call(tool_name="skill_view",
                                     args={"name": "youtube-content"},
                                     session_id=SESSION) is None


class TestRutasSensibles:
    def test_read_env_bloqueado(self, setup):
        as_user("discord:dev1")
        out = plugin._pre_tool_call(tool_name="read_file",
                                    args={"path": "/home/tomas/.hermes/.env"},
                                    session_id=SESSION)
        assert out["action"] == "block"
        assert "sensible" in out["message"]

    def test_terminal_cat_config_bloqueado(self, setup):
        as_user("discord:dev1")
        out = plugin._pre_tool_call(tool_name="terminal",
                                    args={"command": "cat ~/.hermes/config.yaml | grep key"},
                                    session_id=SESSION)
        assert out["action"] == "block"

    def test_terminal_comando_inocuo_pasa(self, setup):
        as_user("discord:dev1")
        assert plugin._pre_tool_call(tool_name="terminal",
                                     args={"command": "ls /tmp && echo hola"},
                                     session_id=SESSION) is None

    def test_admin_con_bypass_lee_env(self, setup):
        as_user("discord:admin1")
        assert plugin._pre_tool_call(tool_name="read_file",
                                     args={"path": "/home/tomas/.hermes/.env"},
                                     session_id=SESSION) is None

    def test_roles_yaml_bloqueado(self, setup):
        as_user("discord:dev1")
        out = plugin._pre_tool_call(
            tool_name="read_file",
            args={"path": "/home/iris/.hermes/plugins/hermes-rbac/roles.yaml"},
            session_id=SESSION)
        assert out["action"] == "block"


class TestContextoSistema:
    def test_sesion_desconocida_es_system(self, setup):
        # cron/subagente/CLI: sin registry entry -> acceso full
        assert plugin._pre_tool_call(tool_name="terminal",
                                     args={"command": "cat /home/iris/.hermes/.env"},
                                     session_id="cron:job123") is None

    def test_registry_ttl_expira(self, setup, monkeypatch):
        as_user("discord:view1")
        # Simular que paso el TTL
        import time
        real = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: real() + 90000)
        assert registry.user_for_session(SESSION) is None
