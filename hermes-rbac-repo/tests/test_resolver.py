"""Tests unitarios del resolver de hermes-rbac (issue #2).

Criterio de done: resolucion de herencia multiple, diamond, ciclo
detectado con error claro, deny gana, wildcard.
"""

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

# El directorio del plugin se llama "hermes-rbac" (guion, no importable
# como paquete). Cargamos resolver.py directamente por ruta.
_spec = importlib.util.spec_from_file_location(
    "resolver", Path(__file__).resolve().parent.parent / "resolver.py")
resolver = importlib.util.module_from_spec(_spec)
sys.modules["resolver"] = resolver
_spec.loader.exec_module(resolver)

RoleResolver = resolver.RoleResolver
SYSTEM_ROLE = resolver.SYSTEM_ROLE
RbacConfigError = resolver.RbacConfigError


def make_resolver(tmp_path, config: dict) -> RoleResolver:
    p = tmp_path / "roles.yaml"
    p.write_text(yaml.safe_dump(config), encoding="utf-8")
    return RoleResolver(config_path=p)


BASE = {
    "fail_closed": True,
    "roles": {
        "viewer": {"toolsets": ["web"], "skills": ["youtube-content"]},
        "dev": {
            "extends": ["viewer"],
            "toolsets": ["terminal", "file"],
            "skills": ["test-driven-development"],
        },
        "admin": {
            "extends": ["dev"],
            "toolsets": ["*"],
            "skills": ["*"],
            "bypass_sensitive_paths": True,
        },
    },
    "users": {
        "discord:111": ["viewer"],
        "discord:222": ["dev"],
        "discord:333": ["admin"],
    },
}


class TestHerencia:
    def test_herencia_simple(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        eff = r.effective("discord:222")
        assert eff.roles == frozenset({"dev", "viewer"})
        assert "terminal" in eff.toolsets and "web" in eff.toolsets
        assert not eff.toolsets_all

    def test_herencia_transitiva_admin(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        eff = r.effective("discord:333")
        assert eff.roles == frozenset({"admin", "dev", "viewer"})
        assert eff.toolsets_all and eff.skills_all
        assert eff.bypass_sensitive_paths

    def test_diamond(self, tmp_path):
        cfg = {
            "roles": {
                "base": {"toolsets": ["web"]},
                "a": {"extends": ["base"], "toolsets": ["terminal"]},
                "b": {"extends": ["base"], "toolsets": ["file"]},
                "top": {"extends": ["a", "b"]},
            },
            "users": {"discord:1": ["top"]},
        }
        r = make_resolver(tmp_path, cfg)
        eff = r.effective("discord:1")
        assert eff.roles == frozenset({"top", "a", "b", "base"})
        assert eff.toolsets == frozenset({"web", "terminal", "file"})

    def test_ciclo_detectado(self, tmp_path):
        cfg = {
            "roles": {
                "a": {"extends": ["b"]},
                "b": {"extends": ["a"]},
            },
            "users": {"discord:1": ["a"]},
        }
        p = tmp_path / "roles.yaml"
        p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        r = RoleResolver(config_path=p)
        assert r.load_error is not None
        assert "ciclo" in r.load_error
        # fail-closed: nadie pasa
        assert r.effective("discord:1") is None

    def test_extiende_rol_inexistente(self, tmp_path):
        cfg = {"roles": {"a": {"extends": ["fantasma"]}}, "users": {}}
        r = make_resolver(tmp_path, cfg)
        assert r.load_error is not None
        assert "no existe" in r.load_error


class TestDenyGana:
    def test_deny_resta_heredado(self, tmp_path):
        cfg = {
            "roles": {
                "dev": {"toolsets": ["terminal", "file", "web"]},
                "dev_restringido": {
                    "extends": ["dev"],
                    "deny": ["terminal"],
                },
            },
            "users": {"discord:1": ["dev_restringido"]},
        }
        r = make_resolver(tmp_path, cfg)
        eff = r.effective("discord:1")
        assert "terminal" not in eff.toolsets
        assert {"file", "web"} <= eff.toolsets


class TestWildcardsYDefault:
    def test_wildcard_users_default(self, tmp_path):
        cfg = {
            "roles": {"guest": {"toolsets": ["web"]}},
            "users": {"*": ["guest"]},
        }
        r = make_resolver(tmp_path, cfg)
        eff = r.effective("discord:cualquiera")
        assert eff is not None and "web" in eff.toolsets

    def test_sin_default_no_autorizado(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        assert r.effective("discord:999") is None

    def test_fail_closed_false_permite_nada_sin_roles(self, tmp_path):
        # fail_closed=False solo afecta a comportamiento del hook ante errores
        # internos; sin roles asignados el usuario igual no tiene acceso.
        cfg = dict(BASE, fail_closed=False)
        r = make_resolver(tmp_path, cfg)
        assert r.effective("discord:999") is None


class TestDecision:
    def test_can_toolset_con_glob(self, tmp_path):
        cfg = {
            "roles": {"r": {"toolsets": ["mcp__github__*"]}},
            "users": {"discord:1": ["r"]},
        }
        r = make_resolver(tmp_path, cfg)
        eff = r.effective("discord:1")
        assert r.can_toolset(eff, "mcp__github__create_issue")
        assert not r.can_toolset(eff, "terminal")

    def test_can_skill(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        eff = r.effective("discord:111")
        assert r.can_skill(eff, "youtube-content")
        assert not r.can_skill(eff, "godmode")
        admin = r.effective("discord:333")
        assert r.can_skill(admin, "godmode")

    def test_can_path_sensible(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        assert not r.can_path(r.effective("discord:222"), sensitive=True)
        assert r.can_path(r.effective("discord:333"), sensitive=True)
        # rutas no sensibles siempre pasan
        assert r.can_path(r.effective("discord:222"), sensitive=False)

    def test_system_full(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        eff = r.system()
        assert eff.is_system and SYSTEM_ROLE in eff.roles
        assert r.can_toolset(eff, "terminal")
        assert r.can_skill(eff, "cualquier-cosa")
        assert r.can_path(eff, sensitive=True)


class TestBootstrap:
    def test_bootstrap_admin_con_config_rota(self, tmp_path):
        p = tmp_path / "roles.yaml"
        p.write_text("roles:\n  a:\n    extends: [a]\n", encoding="utf-8")
        r = RoleResolver(config_path=p)
        assert r.load_error is not None
        # Sin bootstrap configurado: nadie pasa
        assert r.effective("discord:admin1") is None

    def test_bootstrap_admin_pasa_con_config_rota(self, tmp_path):
        p = tmp_path / "roles.yaml"
        p.write_text(
            yaml.safe_dump({
                "bootstrap_admins": ["discord:admin1"],
                "roles": {"a": {"extends": ["a"]}},  # ciclo -> config rota
                "users": {},
            }), encoding="utf-8")
        r = RoleResolver(config_path=p)
        assert r.load_error is not None
        eff = r.effective("discord:admin1")
        assert eff is not None and eff.is_system
        # otro usuario sigue bloqueado
        assert r.effective("discord:otro") is None


class TestMutaciones:
    def test_assign_y_revoke(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        r.assign_role("discord:444", "viewer")
        assert "viewer" in r.roles_for("discord:444")
        eff = r.effective("discord:444")
        assert eff is not None
        r.revoke_role("discord:444", "viewer")
        assert r.effective("discord:444") is None

    def test_assign_rol_inexistente_falla(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        with pytest.raises(RbacConfigError):
            r.assign_role("discord:444", "superpoder")

    def test_reload_por_mtime(self, tmp_path):
        r = make_resolver(tmp_path, BASE)
        assert r.effective("discord:555") is None
        p = tmp_path / "roles.yaml"
        cfg = dict(BASE)
        cfg["users"] = dict(BASE["users"], **{"discord:555": ["viewer"]})
        import time
        time.sleep(0.01)
        p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        r.maybe_reload()
        assert r.effective("discord:555") is not None
