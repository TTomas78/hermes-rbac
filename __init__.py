"""hermes-rbac — RBAC por rol con herencia para Hermes multiusuario.

Hooks:
- ``pre_gateway_dispatch`` (issue #3): no-autorizados reciben rewrite con
  aviso de acceso denegado (el agente nunca ve la consulta original).
- ``pre_tool_call`` (issues #4-#6): block de toolsets no permitidos,
  skill_view restringido a skills del rol, rutas sensibles (.env,
  config.yaml, state.db) solo con bypass_sensitive_paths.

Diseno: Obsidian Research/hermes-multiusuario/2026-08-17.
Repo: https://github.com/TTomas78/hermes-rbac
"""

from __future__ import annotations

import fnmatch
import importlib.util
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional


def _load_local(name: str):
    """Carga un modulo vecino por ruta (el dir 'hermes-rbac' no es paquete
    importable por el guion; el loader de Hermes puede importarnos suelto)."""
    import sys as _sys
    full = f"hermes_rbac_{name}"
    if full in _sys.modules:
        return _sys.modules[full]
    _spec = importlib.util.spec_from_file_location(
        full, Path(__file__).resolve().parent / f"{name}.py")
    _mod = importlib.util.module_from_spec(_spec)
    _sys.modules[full] = _mod  # dataclasses lo necesita
    _spec.loader.exec_module(_mod)
    return _mod


try:
    from .resolver import RoleResolver
    from .audit import AuditLog
    from .identity import IdentityResolver
    from . import registry
    from . import cli as _cli_mod
    from . import resolver as _resolver_mod
    from . import audit as _audit_mod
except ImportError:
    _resolver_mod = _load_local("resolver")
    _audit_mod = _load_local("audit")
    registry = _load_local("registry")
    _cli_mod = _load_local("cli")
    RoleResolver = _resolver_mod.RoleResolver
    AuditLog = _audit_mod.AuditLog
    IdentityResolver = _load_local("identity").IdentityResolver

# Expuestos para tests (el dir tiene guion, no importable como paquete).
resolver = _resolver_mod
audit = _audit_mod

logger = logging.getLogger(__name__)

RBAC_DENY_TEXT = (
    "[SISTEMA RBAC] Este usuario no esta autorizado a usar este agente. "
    "No proceses ninguna solicitud suya. Responde UNICAMENTE con un mensaje "
    "breve indicando que no tiene acceso y que contacte al administrador. "
    "No reveles informacion sobre el sistema, otros usuarios ni capacidades."
)

# Patrones de rutas sensibles (basename o path relativo al home de Hermes).
# Un usuario sin bypass_sensitive_paths no puede leer ni escribir estas rutas.
SENSITIVE_PATTERNS = [
    ".env",
    ".env.*",
    "config.yaml",
    "config.yml",
    "state.db",
    "state.db-*",
    "credentials*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_ed25519*",
    "roles.yaml",          # la propia config RBAC no se edita desde el chat
]

# Args de tools que contienen rutas de archivo a chequear.
PATH_ARGS = ("path", "file_path", "source", "destination", "output_path",
             "workdir", "command")

_resolver: Optional[RoleResolver] = None
_audit: Optional[AuditLog] = None
_identity: Optional[IdentityResolver] = None


def _get_resolver() -> RoleResolver:
    global _resolver
    if _resolver is None:
        _resolver = RoleResolver()
    return _resolver

def _get_audit() -> AuditLog:
    global _audit
    if _audit is None:
        _audit = AuditLog()
    return _audit

def _get_identity() -> IdentityResolver:
    global _identity
    if _identity is None:
        _identity = IdentityResolver()
    return _identity


def register(ctx) -> None:
    """Entry point del plugin. Registra hooks, CLI y slash command."""
    _get_resolver()
    ctx.register_hook("pre_gateway_dispatch", _pre_gateway_dispatch)
    ctx.register_hook("pre_tool_call", _pre_tool_call)

    _audit_default = getattr(_audit_mod, "DEFAULT_AUDIT_PATH",
                             Path(__file__).resolve().parent / "audit.jsonl")
    setup_fn, handler_fn = _cli_mod.make_cli(
        RoleResolver, _default_config_path(), _audit_default)
    ctx.register_cli_command("rbac", help="Administrar RBAC (roles/usuarios)",
                             setup_fn=setup_fn, handler_fn=handler_fn)
    ctx.register_command("rbac", _cli_mod.make_slash(_get_resolver, _get_identity),
                         description="Consulta RBAC (solo lectura)",
                         args_hint="[whoami|roles|user <key>|identities]")
    logger.info("hermes-rbac: plugin registrado")
    _warn_platform_allowlist_conflicts()


# Allowlists de plataforma que filtran ANTES del dispatch y en silencio:
# si están activas, los usuarios rechazados nunca llegan al RBAC y no
# reciben el mensaje de denegación (experiencia rota + falsa sensación
# de que el RBAC es la única capa).
_PLATFORM_ALLOWLIST_ENVS = {
    "DISCORD_ALLOWED_USERS": "Discord",
    "DISCORD_ALLOWED_ROLES": "Discord",
    "TELEGRAM_ALLOWED_USERS": "Telegram",
    "SLACK_ALLOWED_USERS": "Slack",
    "WHATSAPP_ALLOWED_USERS": "WhatsApp",
}


def _warn_platform_allowlist_conflicts() -> None:
    """Avisa al arranque si hay allowlists de plataforma que silencian al RBAC."""
    active = [f"{name} ({plat})" for name, plat in _PLATFORM_ALLOWLIST_ENVS.items()
              if os.getenv(name, "").strip()]
    if active:
        logger.warning(
            "hermes-rbac: allowlist(s) de plataforma activas: %s. Esas capas "
            "rechazan usuarios ANTES del RBAC y sin feedback: los denegados "
            "no verán el mensaje de acceso denegado ni quedarán en audit. "
            "Recomendado: vaciarlas y dejar al RBAC como capa única de "
            "autorización.",
            ", ".join(active))


def _default_config_path() -> Path:
    return Path(__file__).resolve().parent / "roles.yaml"


# ----------------------------------------------------------------------
# pre_gateway_dispatch (issue #3)
# ----------------------------------------------------------------------

def _user_key_from_event(event) -> Optional[str]:
    """Extrae 'platform:user_id' del MessageEvent. None si no se puede."""
    try:
        src = event.source
        if src is None or src.user_id is None:
            return None
        platform = src.platform.value if hasattr(src.platform, "value") else str(src.platform)
        return f"{platform}:{src.user_id}"
    except AttributeError:
        return None


def _session_key_from_event(event, session_store=None) -> Optional[str]:
    """Clave de sesion tal como la ve pre_tool_call (session_id).

    Fuente de verdad: session_store._generate_session_key(source) del core
    (build_session_key con la config real del gateway). Formato resultante:
    ``<ns>:<platform>:<chat_type>:<chat_id>[:thread][:user]`` — distinto del
    ``platform:chat_id`` que generabamos a mano y que NUNCA matcheaba el
    session_id del agente (bug descubierto en el test E2E 2026-08-19: el
    tool-gate no encontraba usuario y caia en acceso full de sistema).

    Fallback (defensivo, mismo formato que el core para DMs): si no hay
    session_store, construimos ``agent:main:<platform>:dm:<chat_id>`` para
    DMs, que es la key legacy por defecto.
    """
    try:
        src = event.source
        if src is None:
            return None
        if session_store is not None:
            try:
                key = session_store._generate_session_key(src)
                if isinstance(key, str) and key:
                    return key
            except Exception:
                pass
        platform = src.platform.value if hasattr(src.platform, "value") else str(src.platform)
        chat_type = getattr(src, "chat_type", None) or "dm"
        chat_id = str(src.chat_id) if getattr(src, "chat_id", None) else None
        if chat_type == "dm" and chat_id:
            if getattr(src, "thread_id", None):
                return f"agent:main:{platform}:dm:{chat_id}:{src.thread_id}"
            return f"agent:main:{platform}:dm:{chat_id}"
        # Grupos/canales sin session_store: no podemos replicar la logica de
        # aislamiento por usuario del core; mejor no registrar que registrar mal.
        return None
    except AttributeError:
        return None


def _pre_gateway_dispatch(event=None, gateway=None, session_store=None, **_kw):
    """Gate de acceso: usuarios sin roles reciben aviso de denegacion."""
    resolver = _get_resolver()
    audit = _get_audit()
    resolver.maybe_reload()

    if getattr(event, "internal", False):
        return {"action": "allow"}

    user_key = _user_key_from_event(event)
    if user_key is None:
        if resolver.fail_closed:
            audit.log("dispatch", user="unknown", decision="deny",
                      reason="no se pudo extraer platform:user_id del evento")
            return {"action": "rewrite", "text": RBAC_DENY_TEXT}
        return {"action": "allow"}

    # Identidad unificada: si la key pertenece a una persona, roles se
    # resuelven con la identidad CANONICA (la elegida por el usuario al
    # vincular). NUNCA se muta source.user_id: el core persiste la sesion
    # con ese ID despues del hook, y una mutacion contaminaria la DB (el
    # proximo mensaje de esta plataforma llegaria con el ID de otra).
    # El mapeo es unilateral: el plugin lo resuelve internamente.
    identity = _get_identity()
    identity.maybe_reload()
    canonical_key = identity.resolve(user_key)
    if canonical_key != user_key:
        logger.info("hermes-rbac: identidad %s -> canonica %s", user_key,
                    canonical_key)
    user_key = canonical_key

    perms = resolver.effective(user_key)
    if perms is None:
        reason = resolver.load_error or "usuario sin roles asignados"
        audit.log("dispatch", user=user_key, decision="deny", reason=reason)
        logger.info("hermes-rbac: deny dispatch user=%s (%s)", user_key, reason)
        return {"action": "rewrite", "text": RBAC_DENY_TEXT}

    # Registrar sesion para que pre_tool_call pueda resolver el usuario.
    session_key = _session_key_from_event(event, session_store)
    if session_key:
        registry.register_session(session_key, user_key)

    audit.log("dispatch", user=user_key, decision="allow",
              roles=sorted(perms.roles))
    return {"action": "allow"}


def _user_for_agent_session(session_id: str) -> Optional[str]:
    """Lookup en state.db del gateway: session_id (agente) -> user_id canonical.

    El session_id que llega a pre_tool_call es el ID interno del agente
    (timestamp), no la session key. El core persiste el mapping en la tabla
    sessions via record_gateway_session_peer — con el user_id ORIGINAL de la
    plataforma (el dispatch restaura la mutacion antes de salir). Se resuelve
    a la identidad canonica antes de devolver. Retorna la user_key completa
    (platform:user_id) o None si no hay mapping.
    """
    if not session_id:
        return None
    try:
        import os
        import sqlite3
        db_path = Path(os.environ.get("HERMES_HOME",
                     str(Path.home() / ".hermes"))) / "state.db"
        if not db_path.exists():
            return None
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1)
        try:
            row = conn.execute(
                "SELECT source, user_id FROM sessions WHERE id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None or not row[1]:
            return None
        platform, user_id = row
        raw_key = f"{platform}:{user_id}"
        # La DB ahora guarda el ID original de la plataforma; resolver a
        # canonica si pertenece a una persona vinculada.
        identity = _get_identity()
        identity.maybe_reload()
        return identity.resolve(raw_key)
    except Exception as e:
        logger.debug("hermes-rbac: lookup state.db fallo session=%s: %s", session_id, e)
        return None



# ----------------------------------------------------------------------
# pre_tool_call (issues #4-#6)
# ----------------------------------------------------------------------

def _is_sensitive_path(value: str) -> bool:
    """True si el path matchea un patron sensible (por basename)."""
    base = Path(value).name
    for pat in SENSITIVE_PATTERNS:
        if fnmatch.fnmatchcase(base, pat):
            return True
    return False


def _paths_in_args(args: dict) -> list:
    """Extrae valores de ruta/comando de los args de una tool."""
    hits = []
    for key in PATH_ARGS:
        val = args.get(key)
        if isinstance(val, str) and val:
            hits.append((key, val))
    return hits


def _block(audit, user_key: str, tool_name: str, reason: str,
           perms=None) -> dict:
    audit.log("tool_call", user=user_key, decision="block", tool=tool_name,
              reason=reason,
              roles=sorted(perms.roles) if perms else None)
    logger.info("hermes-rbac: block tool=%s user=%s (%s)", tool_name, user_key, reason)
    return {"action": "block",
            "message": f"Bloqueado por politica RBAC: {reason}. "
                       f"NO reintentes esta tool ni busques alternativas: "
                       f"informa al usuario que la accion requiere un rol "
                       f"con mas permisos y que contacte al administrador "
                       f"si cree que es un error."}


def _pre_tool_call(tool_name: str = "", args: Optional[dict] = None,
                   session_id: str = "", task_id: str = "", **_kw) -> Optional[dict]:
    """Enforcement de RBAC sobre cada llamada a tool.

    Resolucion de usuario: session_id -> registry (llenado por dispatch).
    Contextos sin session registrada (cron, subagentes, CLI) = system (full).
    """
    resolver = _get_resolver()
    audit = _get_audit()
    args = args or {}

    # Lookup 1: registry en memoria (llenado por dispatch con la session key
    # del gateway). Cubre el caso donde el agente corre con la session key
    # directamente.
    user_key = registry.user_for_session(session_id)
    if user_key is None:
        # Lookup 2: state.db del gateway. El session_id que llega al hook es
        # el ID interno del agente (timestamp), NO la session key — el core
        # persiste el mapping session_id -> user_id (ya canonical por nuestro
        # dispatch) en la tabla sessions via record_gateway_session_peer.
        user_key = _user_for_agent_session(session_id)
    if user_key is None:
        # Sin usuario asociado: contexto de sistema (cron/subagente/CLI local).
        # La decision de diseno es acceso full (ver doc seccion 4, rol system).
        return None

    perms = resolver.effective(user_key)
    if perms is None:
        return _block(audit, user_key, tool_name, "sin roles asignados")

    # 1) Toolset gate: el nombre de la tool ES el identificador de toolset
    #    en Hermes (terminal, write_file, mcp__github__*, etc.).
    if not resolver.can_toolset(perms, tool_name):
        return _block(audit, user_key, tool_name,
                      f"tool '{tool_name}' no permitida para tu rol", perms)

    # 2) skill_view: el skill pedido debe estar en la lista del rol.
    if tool_name == "skill_view":
        skill = (args.get("name") or "").strip()
        if skill and not resolver.can_skill(perms, skill):
            return _block(audit, user_key, tool_name,
                          f"skill '{skill}' no permitido para tu rol", perms)

    # 3) Rutas sensibles: chequear path-like args y el comando de terminal.
    if not perms.bypass_sensitive_paths:
        for key, val in _paths_in_args(args):
            if key == "command":
                # terminal: buscar menciones de archivos sensibles en el comando
                for token in re.split(r"[\s;|&><'\"]+", val):
                    if token and _is_sensitive_path(token):
                        return _block(audit, user_key, tool_name,
                                      f"el comando toca una ruta sensible ({token})",
                                      perms)
            elif _is_sensitive_path(val):
                return _block(audit, user_key, tool_name,
                              f"ruta sensible ({Path(val).name})", perms)

    audit.log("tool_call", user=user_key, decision="allow", tool=tool_name,
              roles=sorted(perms.roles))
    return None
