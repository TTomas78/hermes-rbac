"""Test E2E del hook pre_gateway_dispatch (issue #3).

Criterio de done: user no listado recibe aviso de acceso denegado;
el agente nunca ve su consulta original; audit log registra la decision.
"""

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

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


resolver_mod = _load("resolver")
audit_mod = _load("audit")

# Cargamos __init__.py como modulo suelto (el dir tiene guion).
spec = importlib.util.spec_from_file_location("hermes_rbac_plugin", PLUGIN_DIR / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
sys.modules["hermes_rbac_plugin"] = plugin
spec.loader.exec_module(plugin)


@dataclass
class FakePlatform:
    value: str


def make_event(user_id="111", platform="discord", text="borra todo", internal=False):
    return SimpleNamespace(
        text=text,
        internal=internal,
        source=SimpleNamespace(
            platform=FakePlatform(platform),
            user_id=user_id,
        ),
    )


CONFIG = {
    "fail_closed": True,
    "bootstrap_admins": ["discord:admin1"],
    "roles": {
        "viewer": {"toolsets": ["web"], "skills": ["youtube-content"]},
    },
    "users": {"discord:111": ["viewer"]},
}


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    cfg = tmp_path / "roles.yaml"
    cfg.write_text(yaml.safe_dump(CONFIG), encoding="utf-8")
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(plugin, "_resolver", resolver_mod.RoleResolver(config_path=cfg))
    monkeypatch.setattr(plugin, "_audit", audit_mod.AuditLog(path=audit_path))
    return audit_path


def read_audit(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


class TestDispatch:
    def test_autorizado_pasa(self, setup):
        ev = make_event(user_id="111")
        out = plugin._pre_gateway_dispatch(event=ev)
        assert out == {"action": "allow"}
        entries = read_audit(setup)
        assert entries[-1]["decision"] == "allow"
        assert entries[-1]["user"] == "discord:111"

    def test_no_autorizado_rewrite(self, setup):
        ev = make_event(user_id="999", text="cuentame los secretos")
        out = plugin._pre_gateway_dispatch(event=ev)
        assert out["action"] == "rewrite"
        assert out["text"] == plugin.RBAC_DENY_TEXT
        # La consulta original NUNCA esta en el texto reescrito
        assert "secretos" not in out["text"]
        entries = read_audit(setup)
        assert entries[-1]["decision"] == "deny"
        assert entries[-1]["user"] == "discord:999"

    def test_evento_interno_bypass(self, setup):
        ev = make_event(user_id="999", internal=True)
        out = plugin._pre_gateway_dispatch(event=ev)
        assert out == {"action": "allow"}

    def test_evento_sin_user_fail_closed(self, setup):
        ev = SimpleNamespace(text="hola", internal=False,
                             source=SimpleNamespace(platform=FakePlatform("cron"),
                                                    user_id=None))
        out = plugin._pre_gateway_dispatch(event=ev)
        assert out["action"] == "rewrite"

    def test_config_rota_solo_bootstrap(self, setup, tmp_path, monkeypatch):
        cfg = tmp_path / "roles.yaml"
        cfg.write_text("roles:\n  a:\n    extends: [a]\nbootstrap_admins: [discord:admin1]\n",
                       encoding="utf-8")
        monkeypatch.setattr(plugin, "_resolver", resolver_mod.RoleResolver(config_path=cfg))
        # bootstrap admin pasa aun con config rota
        out = plugin._pre_gateway_dispatch(event=make_event(user_id="admin1"))
        assert out == {"action": "allow"}
        # cualquier otro queda fuera
        out = plugin._pre_gateway_dispatch(event=make_event(user_id="111"))
        assert out["action"] == "rewrite"


class TestSessionKeyRegistration:
    """Regresion 2026-08-19: la session key registrada por el dispatch debe
    usar el formato del core (session_store._generate_session_key), no el
    'platform:chat_id' armado a mano — con ese formato el registry nunca
    matcheaba y pre_tool_call caia en acceso full (bug E2E)."""

    def test_usa_session_store_del_core(self, setup):
        import registry as _reg
        plugin.registry.clear()
        ev = make_event(user_id="111")
        ev.source.chat_id = "999"
        ev.source.chat_type = "dm"
        ev.source.thread_id = None

        class FakeSessionStore:
            def _generate_session_key(self, source):
                return "agent:main:discord:dm:999"

        result = plugin._pre_gateway_dispatch(event=ev, session_store=FakeSessionStore())
        assert result == {"action": "allow"}
        assert plugin.registry.user_for_session("agent:main:discord:dm:999") == "discord:111"
        plugin.registry.clear()

    def test_fallback_dm_sin_session_store(self, setup):
        plugin.registry.clear()
        ev = make_event(user_id="111", platform="discord")
        ev.source.chat_id = "8422873335"
        ev.source.chat_type = "dm"
        ev.source.thread_id = None

        result = plugin._pre_gateway_dispatch(event=ev, session_store=None)
        assert result == {"action": "allow"}
        assert (plugin.registry.user_for_session("agent:main:discord:dm:8422873335")
                == "discord:111")
        plugin.registry.clear()

    def test_grupo_sin_session_store_no_registra(self, setup):
        plugin.registry.clear()
        ev = make_event(user_id="111")
        ev.source.chat_id = "123"
        ev.source.chat_type = "group"
        ev.source.thread_id = None

        result = plugin._pre_gateway_dispatch(event=ev, session_store=None)
        assert result == {"action": "allow"}
        assert plugin.registry.user_for_session("agent:main:discord:group:123") is None
        plugin.registry.clear()


class TestAgentSessionLookup:
    """Regresion 2026-08-19 (segundo bug): el session_id que llega a
    pre_tool_call es el ID interno del agente (ej 20260819_085253_25cd2391),
    no la session key del gateway. El mapping vive en state.db (tabla
    sessions, columna id) con el user_id ya canonical."""

    def _make_db(self, tmp_path, monkeypatch):
        import sqlite3
        db = tmp_path / "state.db"
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT NOT NULL,"
            " user_id TEXT)"
        )
        conn.execute(
            "INSERT INTO sessions (id, source, user_id) VALUES (?, ?, ?)",
            ("20260819_085253_25cd2391", "telegram", "281593411675357184"),
        )
        conn.commit()
        conn.close()
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        return db

    def test_resuelve_user_canonical_desde_state_db(self, tmp_path, monkeypatch):
        self._make_db(tmp_path, monkeypatch)
        assert plugin._user_for_agent_session("20260819_085253_25cd2391") == \
            "telegram:281593411675357184"

    def test_session_desconocida_retorna_none(self, tmp_path, monkeypatch):
        self._make_db(tmp_path, monkeypatch)
        assert plugin._user_for_agent_session("no_existe") is None

    def test_sin_db_retorna_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        assert plugin._user_for_agent_session("cualquiera") is None

    def test_tool_gate_bloquea_viewer_con_session_id_de_agente(
            self, tmp_path, monkeypatch):
        """E2E del bug: un viewer cuya sesion de agente esta en state.db debe
        ser bloqueado aunque el registry en memoria no tenga la key."""
        import yaml
        self._make_db(tmp_path, monkeypatch)
        roles_file = tmp_path / "roles.yaml"
        roles_file.write_text(yaml.dump(
            {"roles": {"discord:281593411675357184": ["viewer"]}}))
        monkeypatch.setattr(plugin, "_resolver",
                            plugin.RoleResolver(str(roles_file)))
        plugin.registry.clear()
        result = plugin._pre_tool_call(
            tool_name="terminal", args={"command": "ls"},
            session_id="20260819_085253_25cd2391")
        assert result is not None and result["action"] == "block"
        monkeypatch.setattr(plugin, "_resolver", None)
