"""Tests del CLI `hermes rbac` y mutaciones (issues #7/#9).

Criterio de done: assign/revoke modifican roles.yaml y se reflejan en la
resolucion; assign a rol inexistente falla; audit muestra entradas.
"""

import argparse
import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

PLUGIN_DIR = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location("hermes_rbac_plugin", PLUGIN_DIR / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
sys.modules["hermes_rbac_plugin"] = plugin
spec.loader.exec_module(plugin)

resolver_mod = plugin.resolver
cli_mod = plugin._cli_mod

CONFIG = {
    "fail_closed": True,
    "roles": {
        "viewer": {"toolsets": ["web_search"]},
        "dev": {"extends": ["viewer"], "toolsets": ["terminal"]},
    },
    "users": {"discord:u1": ["viewer"]},
}


@pytest.fixture()
def env(tmp_path):
    cfg = tmp_path / "roles.yaml"
    cfg.write_text(yaml.safe_dump(CONFIG), encoding="utf-8")
    audit_path = tmp_path / "audit.jsonl"
    setup_fn, handler = cli_mod.make_cli(resolver_mod.RoleResolver, cfg, audit_path)
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()
    rbac = subs.add_parser("rbac")
    setup_fn(rbac)
    rbac.set_defaults(func=handler)
    return parser, cfg, audit_path


def run(parser, *argv):
    args = parser.parse_args(list(argv))
    args.func(args)


class TestCliLectura:
    def test_roles(self, env, capsys):
        parser, _, _ = env
        run(parser, "rbac", "roles")
        out = capsys.readouterr().out
        assert "viewer" in out and "dev" in out
        assert "terminal" in out  # permiso resuelto de dev

    def test_users(self, env, capsys):
        parser, _, _ = env
        run(parser, "rbac", "users")
        assert "discord:u1" in capsys.readouterr().out

    def test_user_detalle(self, env, capsys):
        parser, _, _ = env
        run(parser, "rbac", "user", "discord:u1")
        out = capsys.readouterr().out
        assert "viewer" in out and "web_search" in out

    def test_user_sin_acceso(self, env, capsys):
        parser, _, _ = env
        run(parser, "rbac", "user", "discord:nadie")
        assert "SIN ACCESO" in capsys.readouterr().out


class TestCliMutaciones:
    def test_assign(self, env, capsys):
        parser, cfg, _ = env
        run(parser, "rbac", "assign", "discord:u2", "dev")
        raw = yaml.safe_load(cfg.read_text())
        assert "dev" in raw["users"]["discord:u2"]
        assert "OK" in capsys.readouterr().out

    def test_assign_rol_inexistente_falla(self, env):
        parser, _, _ = env
        with pytest.raises(SystemExit):
            run(parser, "rbac", "assign", "discord:u2", "superadmin")

    def test_revoke(self, env, capsys):
        parser, cfg, _ = env
        run(parser, "rbac", "revoke", "discord:u1", "viewer")
        raw = yaml.safe_load(cfg.read_text())
        assert raw["users"]["discord:u1"] == []
        assert "OK" in capsys.readouterr().out

    def test_assign_respeta_permisos(self, env):
        """Un user recien asignado a dev puede usar terminal (resolucion real)."""
        parser, cfg, _ = env
        run(parser, "rbac", "assign", "discord:u3", "dev")
        resolver = resolver_mod.RoleResolver(config_path=cfg)
        perms = resolver.effective("discord:u3")
        assert resolver.can_toolset(perms, "terminal")
        assert resolver.can_toolset(perms, "web_search")  # heredado de viewer

    def test_audit(self, env, capsys):
        parser, _, audit_path = env
        plugin._audit = plugin.AuditLog(path=audit_path)
        plugin._audit.log("dispatch", user="discord:u1", decision="deny", reason="test")
        run(parser, "rbac", "audit")
        out = capsys.readouterr().out
        assert "discord:u1" in out and "deny" in out


class TestSlash:
    def test_roles(self, env):
        parser, cfg, _ = env
        resolver = resolver_mod.RoleResolver(config_path=cfg)
        slash = cli_mod.make_slash(lambda: resolver)
        out = slash("roles")
        assert "viewer" in out and "dev" in out

    def test_user(self, env):
        parser, cfg, _ = env
        resolver = resolver_mod.RoleResolver(config_path=cfg)
        slash = cli_mod.make_slash(lambda: resolver)
        assert "viewer" in slash("user discord:u1")
        assert "sin acceso" in slash("user discord:nadie")

    def test_help_default(self, env):
        parser, cfg, _ = env
        resolver = resolver_mod.RoleResolver(config_path=cfg)
        slash = cli_mod.make_slash(lambda: resolver)
        out = slash("")
        assert "hermes rbac" in out  # mutaciones solo por CLI
