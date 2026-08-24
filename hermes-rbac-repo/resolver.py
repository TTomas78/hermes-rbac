"""Resolver de roles para hermes-rbac.

Carga ``roles.yaml`` y resuelve permisos efectivos por usuario:

- Herencia múltiple via ``extends: [rol_a, rol_b]``.
- Permisos aditivos (union), pero ``deny`` explicito gana siempre.
- Deteccion de ciclos con error claro.
- Wildcards: ``"*"`` en toolsets/skills = todo; ``"*"`` en users = default.
- ``fail_closed: true`` (default): ante cualquier error de config, deny.

Sin dependencias externas (yaml solo; stdlib).
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path.home() / ".hermes" / "plugins" / "hermes-rbac" / "roles.yaml"

# Rol sintetico para contextos sin usuario (cron, subagentes).
SYSTEM_ROLE = "system"


class RbacConfigError(Exception):
    """Error de configuracion de roles.yaml (ciclo, rol inexistente, etc.)."""


@dataclass(frozen=True)
class EffectivePermissions:
    """Permisos efectivos resueltos para un usuario."""

    roles: FrozenSet[str]                      # roles directos + heredados (transitivo)
    toolsets: FrozenSet[str]                   # toolsets permitidos ("*" si aplica)
    skills: FrozenSet[str]                     # skills permitidos para skill_view
    toolsets_all: bool = False                 # "*" en toolsets
    skills_all: bool = False                   # "*" en skills
    bypass_sensitive_paths: bool = False       # puede leer .env/config.yaml
    is_system: bool = False                    # contexto sin usuario (cron/subagente)


@dataclass
class Role:
    name: str
    extends: List[str] = field(default_factory=list)
    toolsets: List[str] = field(default_factory=list)
    skills: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    bypass_sensitive_paths: bool = False


class RoleResolver:
    """Resuelve roles -> permisos efectivos. Thread-safe para lectura."""

    def __init__(self, config_path: Optional[Path] = None):
        self._config_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        self._roles: Dict[str, Role] = {}
        self._users: Dict[str, List[str]] = {}
        self._default_roles: List[str] = []
        self._fail_closed: bool = True
        self._bootstrap_admins: List[str] = []
        self._load_error: Optional[str] = None
        self._mtime: float = 0.0
        self.reload()

    # ------------------------------------------------------------------
    # Carga y validacion
    # ------------------------------------------------------------------

    def reload(self) -> bool:
        """(Re)carga roles.yaml. Devuelve True si la config es valida."""
        try:
            raw = self._read_yaml()
            roles, users, default_roles, fail_closed, bootstrap = self._parse(raw)
            self._validate(roles)
            # Cache de resolucion: nombre de rol -> EffectivePermissions parcial
            self._roles = roles
            self._users = users
            self._default_roles = default_roles
            self._fail_closed = fail_closed
            self._bootstrap_admins = bootstrap
            self._role_cache: Dict[str, EffectivePermissions] = {}
            self._load_error = None
            try:
                self._mtime = self._config_path.stat().st_mtime
            except OSError:
                self._mtime = 0.0
            return True
        except Exception as e:
            self._load_error = str(e)
            logger.error("hermes-rbac: error cargando %s: %s", self._config_path, e)
            # Bootstrap admins: son el salvavidas del fail-closed, rescatarlos
            # aunque el YAML este roto. Primero intento el parse normal (cubre
            # ciclos/roles invalidos con YAML valido); si el YAML en si esta
            # roto, fallback a scan por lineas de la seccion bootstrap_admins.
            try:
                raw = self._read_yaml()
                self._bootstrap_admins = list(raw.get("bootstrap_admins") or [])
                if not self._roles:  # primera carga rota: estado vacio
                    self._role_cache = {}
            except Exception:
                self._bootstrap_admins = self._scan_bootstrap_admins()
            return False

    def _scan_bootstrap_admins(self) -> List[str]:
        """Extrae bootstrap_admins por lineas cuando el YAML no parsea."""
        import re
        try:
            text = self._config_path.read_text(encoding="utf-8")
        except OSError:
            return []
        m = re.search(r"(?ms)^bootstrap_admins:\s*\n((?:[ \t]+-\s*\S+[^\n]*\n?)+)", text)
        if not m:
            return []
        return [x.strip().strip("'\"") for x in re.findall(r"-\s*(\S+)", m.group(1))]

    def maybe_reload(self) -> None:
        """Recarga solo si el archivo cambio (cheap mtime check)."""
        try:
            mtime = self._config_path.stat().st_mtime
        except OSError:
            mtime = 0.0
        if mtime != self._mtime:
            self.reload()

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    @property
    def fail_closed(self) -> bool:
        return self._fail_closed

    def _read_yaml(self) -> Dict[str, Any]:
        if not self._config_path.exists():
            raise RbacConfigError(f"roles.yaml no existe: {self._config_path}")
        with open(self._config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise RbacConfigError("roles.yaml debe ser un mapping YAML")
        return data

    def _parse(self, raw: Dict[str, Any]):
        roles: Dict[str, Role] = {}
        for name, spec in (raw.get("roles") or {}).items():
            if not isinstance(spec, dict):
                raise RbacConfigError(f"rol {name!r}: spec debe ser un mapping")
            extends = spec.get("extends") or []
            if isinstance(extends, str):
                extends = [extends]
            roles[name] = Role(
                name=name,
                extends=list(extends),
                toolsets=list(spec.get("toolsets") or []),
                skills=list(spec.get("skills") or []),
                deny=list(spec.get("deny") or []),
                bypass_sensitive_paths=bool(spec.get("bypass_sensitive_paths", False)),
            )

        users: Dict[str, List[str]] = {}
        for user_key, uroles in (raw.get("users") or {}).items():
            if isinstance(uroles, str):
                uroles = [uroles]
            users[str(user_key)] = list(uroles or [])

        default_roles = users.pop("*", [])
        fail_closed = bool(raw.get("fail_closed", True))
        bootstrap = list(raw.get("bootstrap_admins") or [])
        return roles, users, default_roles, fail_closed, bootstrap

    def _validate(self, roles: Dict[str, Role]) -> None:
        # Referencias de extends deben existir
        for role in roles.values():
            for parent in role.extends:
                if parent not in roles:
                    raise RbacConfigError(
                        f"rol {role.name!r} extiende {parent!r} que no existe")
        # Deteccion de ciclos (DFS con colores)
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {name: WHITE for name in roles}

        def visit(name: str, stack: List[str]) -> None:
            color[name] = GRAY
            stack.append(name)
            for parent in roles[name].extends:
                if color[parent] == GRAY:
                    cycle = " -> ".join(stack + [parent])
                    raise RbacConfigError(f"ciclo de herencia detectado: {cycle}")
                if color[parent] == WHITE:
                    visit(parent, stack)
            stack.pop()
            color[name] = BLACK

        for name in roles:
            if color[name] == WHITE:
                visit(name, [])

    # ------------------------------------------------------------------
    # Resolucion
    # ------------------------------------------------------------------

    def roles_for(self, user_key: str) -> List[str]:
        """Roles directos asignados a un usuario ('platform:id')."""
        return self._users.get(user_key, self._default_roles)

    def _resolve_role(self, name: str, _acc: Optional[Set[str]] = None) -> Set[str]:
        """Devuelve el conjunto transitivo de roles (incluye el propio)."""
        if _acc is None:
            _acc = set()
        if name in _acc:
            return _acc
        _acc.add(name)
        role = self._roles.get(name)
        if role:
            for parent in role.extends:
                self._resolve_role(parent, _acc)
        return _acc

    def effective(self, user_key: str) -> Optional[EffectivePermissions]:
        """Permisos efectivos del usuario. None = no autorizado (sin roles)."""
        direct = self.roles_for(user_key)
        if not direct:
            # Bootstrap de emergencia: solo si la config esta rota/ausente
            if self._load_error and user_key in self._bootstrap_admins:
                return self._system_permissions(is_bootstrap=True)
            return None
        all_roles: Set[str] = set()
        for r in direct:
            if r not in self._roles:
                logger.warning("hermes-rbac: usuario %s tiene rol inexistente %r",
                               user_key, r)
                continue
            all_roles |= self._resolve_role(r)
        if not all_roles:
            return None

        toolsets: Set[str] = set()
        skills: Set[str] = set()
        deny: Set[str] = set()
        bypass = False
        for rname in all_roles:
            role = self._roles[rname]
            toolsets |= set(role.toolsets)
            skills |= set(role.skills)
            deny |= set(role.deny)
            bypass = bypass or role.bypass_sensitive_paths

        toolsets -= deny
        skills -= deny
        toolsets_all = "*" in toolsets
        skills_all = "*" in skills
        return EffectivePermissions(
            roles=frozenset(all_roles),
            toolsets=frozenset(toolsets),
            skills=frozenset(skills),
            toolsets_all=toolsets_all,
            skills_all=skills_all,
            bypass_sensitive_paths=bypass,
        )

    def _system_permissions(self, is_bootstrap: bool = False) -> EffectivePermissions:
        return EffectivePermissions(
            roles=frozenset({SYSTEM_ROLE if not is_bootstrap else "bootstrap-admin"}),
            toolsets=frozenset(),
            skills=frozenset(),
            toolsets_all=True,
            skills_all=True,
            bypass_sensitive_paths=True,
            is_system=True,
        )

    def system(self) -> EffectivePermissions:
        """Permisos full para contextos sin usuario (cron, subagentes)."""
        return self._system_permissions()

    # ------------------------------------------------------------------
    # Consultas de decision
    # ------------------------------------------------------------------

    def can_toolset(self, perms: EffectivePermissions, toolset: str) -> bool:
        if perms.is_system or perms.toolsets_all:
            return True
        return any(fnmatch.fnmatchcase(toolset, pat) for pat in perms.toolsets)

    def can_skill(self, perms: EffectivePermissions, skill: str) -> bool:
        if perms.is_system or perms.skills_all:
            return True
        return any(fnmatch.fnmatchcase(skill, pat) for pat in perms.skills)

    def can_path(self, perms: EffectivePermissions, sensitive: bool) -> bool:
        """sensitive=True si la ruta matchea sensitive_paths."""
        if not sensitive:
            return True
        return perms.is_system or perms.bypass_sensitive_paths

    # ------------------------------------------------------------------
    # Mutaciones (para CLI)
    # ------------------------------------------------------------------

    def assign_role(self, user_key: str, role: str) -> None:
        if role not in self._roles:
            raise RbacConfigError(f"rol {role!r} no existe")
        raw = self._read_yaml()
        users = raw.setdefault("users", {})
        current = users.get(user_key, [])
        if isinstance(current, str):
            current = [current]
        if role not in current:
            current.append(role)
        users[user_key] = current
        self._write_yaml(raw)

    def revoke_role(self, user_key: str, role: str) -> None:
        raw = self._read_yaml()
        users = raw.get("users") or {}
        current = users.get(user_key, [])
        if isinstance(current, str):
            current = [current]
        if role in current:
            current.remove(role)
            users[user_key] = current
            self._write_yaml(raw)

    def _write_yaml(self, raw: Dict[str, Any]) -> None:
        with open(self._config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(raw, f, allow_unicode=True, sort_keys=False)
        self.reload()

    # ------------------------------------------------------------------
    # Introspeccion (para CLI / slash commands)
    # ------------------------------------------------------------------

    def describe_roles(self) -> Dict[str, Dict[str, Any]]:
        out = {}
        for name, role in self._roles.items():
            resolved = sorted(self._resolve_role(name))
            eff_toolsets: Set[str] = set()
            eff_skills: Set[str] = set()
            deny: Set[str] = set(role.deny)
            for rname in resolved:
                r = self._roles[rname]
                eff_toolsets |= set(r.toolsets)
                eff_skills |= set(r.skills)
                deny |= set(r.deny)
            out[name] = {
                "extends": role.extends,
                "resolved_roles": resolved,
                "toolsets": sorted(eff_toolsets - deny),
                "skills": sorted(eff_skills - deny),
                "deny": sorted(deny),
                "bypass_sensitive_paths": any(
                    self._roles[r].bypass_sensitive_paths for r in resolved),
            }
        return out

    def list_users(self) -> Dict[str, List[str]]:
        out = dict(self._users)
        if self._default_roles:
            out["*"] = self._default_roles
        return out
