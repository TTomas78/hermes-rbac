"""CLI `hermes rbac ...` para hermes-rbac (issue #7).

Subcomandos: roles, users, user, assign, revoke, reload, audit, identities,
link-challenge, link-confirm, unlink.
Las mutaciones son SOLO por CLI (decision de diseno): evita auto-elevacion
de privilegios desde el chat.
"""

from __future__ import annotations

import json
from typing import Any


def _identity_mod():
    """Carga identity.py por ruta (el dir 'hermes-rbac' no es paquete)."""
    import importlib.util
    import sys
    from pathlib import Path
    if "rbac_identity" in sys.modules:
        return sys.modules["rbac_identity"]
    spec = importlib.util.spec_from_file_location(
        "rbac_identity", Path(__file__).resolve().parent / "identity.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rbac_identity"] = mod
    spec.loader.exec_module(mod)
    return mod


def make_cli(resolver_cls, default_config_path, default_audit_path):
    """Fabrica (setup_fn, handler_fn) con paths inyectados para testabilidad."""

    def setup(sub) -> None:
        sub.add_argument("--config", default=str(default_config_path),
                         help="Path a roles.yaml (default: el del plugin)")
        cmds = sub.add_subparsers(dest="action", required=True)

        cmds.add_parser("roles", help="Lista roles con permisos resueltos")
        cmds.add_parser("users", help="Lista usuarios y sus roles")

        p_user = cmds.add_parser("user", help="Detalle de un usuario")
        p_user.add_argument("user_key", help='Ej: "discord:123456"')

        p_assign = cmds.add_parser("assign", help="Asigna un rol a un usuario")
        p_assign.add_argument("user_key")
        p_assign.add_argument("role")

        p_revoke = cmds.add_parser("revoke", help="Quita un rol a un usuario")
        p_revoke.add_argument("user_key")
        p_revoke.add_argument("role")

        cmds.add_parser("reload", help="Recarga roles.yaml desde disco")

        p_audit = cmds.add_parser("audit", help="Ultimas N entradas del audit log")
        p_audit.add_argument("-n", "--last", type=int, default=20)

        cmds.add_parser("identities",
                        help="Lista personas vinculadas (identities.yaml)")

        p_ch = cmds.add_parser(
            "link-challenge",
            help="Genera codigo LINK-XXXXXX para vincular esta identidad")
        p_ch.add_argument("user", help="Tu key platform:user_id en ESTA plataforma")

        p_cf = cmds.add_parser(
            "link-confirm",
            help="Consume el codigo y vincula esta identidad con la origen")
        p_cf.add_argument("user", help="Tu key platform:user_id en ESTA plataforma")
        p_cf.add_argument("code", help="Codigo LINK-XXXXXX generado en la otra")
        p_cf.add_argument("--keep-memory", required=True,
                          choices=["a", "b"],
                          help="Que memoria conservar: a=origen del codigo, b=vos. "
                               "La otra queda archivada (no se borra)")

        p_ul = cmds.add_parser("unlink", help="Desvincula una identidad")
        p_ul.add_argument("user")

    def handler(args) -> None:
        resolver = resolver_cls(config_path=args.config)
        resolver.reload()

        if args.action == "roles":
            desc = resolver.describe_roles()
            if not desc:
                print("(sin roles definidos)")
                return
            for name, info in sorted(desc.items()):
                hereda = f" extends={info['extends']}" if info["extends"] else ""
                bypass = " [bypass-sensitive]" if info["bypass_sensitive_paths"] else ""
                print(f"{name}{hereda}{bypass}")
                print(f"  resuelve: {', '.join(info['resolved_roles'])}")
                print(f"  toolsets: {', '.join(info['toolsets']) or '(ninguno)'}")
                print(f"  skills:   {', '.join(info['skills']) or '(ninguno)'}")
                if info["deny"]:
                    print(f"  deny:     {', '.join(info['deny'])}")

        elif args.action == "users":
            raw = resolver._read_yaml()
            users = raw.get("users") or {}
            if not users:
                print("(sin usuarios asignados)")
                return
            for key, roles in sorted(users.items()):
                print(f"{key}: {', '.join(roles) if isinstance(roles, list) else roles}")

        elif args.action == "user":
            perms = resolver.effective(args.user_key)
            if perms is None:
                print(f"{args.user_key}: SIN ACCESO ({resolver.load_error or 'sin roles'})")
                return
            print(f"{args.user_key}")
            print(f"  roles:    {', '.join(sorted(perms.roles))}")
            print(f"  toolsets: {', '.join(sorted(perms.toolsets)) or '(ninguno)'}")
            print(f"  skills:   {', '.join(sorted(perms.skills)) or '(ninguno)'}")
            print(f"  bypass_sensitive_paths: {perms.bypass_sensitive_paths}")

        elif args.action == "assign":
            if args.role not in resolver.describe_roles():
                print(f"ERROR: rol '{args.role}' no existe en roles.yaml")
                raise SystemExit(1)
            resolver.assign_role(args.user_key, args.role)
            print(f"OK: {args.user_key} ahora tiene rol '{args.role}'")

        elif args.action == "revoke":
            resolver.revoke_role(args.user_key, args.role)
            print(f"OK: rol '{args.role}' quitado de {args.user_key}")

        elif args.action == "reload":
            resolver.reload(force=True)
            if resolver.load_error:
                print(f"ERROR al recargar: {resolver.load_error}")
                raise SystemExit(1)
            print("OK: roles.yaml recargado")

        elif args.action == "audit":
            path = default_audit_path
            if not path.exists():
                print("(audit log vacio)")
                return
            lines = path.read_text(encoding="utf-8").splitlines()
            for line in lines[-args.last:]:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                extra = f" tool={e['tool']}" if e.get("tool") else ""
                print(f"{e['ts']} {e['event']:10s} {e['user'] or '-':22s} "
                      f"{e['decision']}{extra} {e.get('reason') or ''}")

        elif args.action == "identities":
            identity = _identity_mod().IdentityResolver()
            persons = identity.describe_persons()
            if not persons:
                print("(sin personas vinculadas — identities.yaml vacio o ausente)")
                return
            for pid, p in persons.items():
                print(f"{pid}  canonical={p['canonical']}")
                for key in p["identities"]:
                    mark = " *" if key == p["canonical"] else ""
                    print(f"  - {key}{mark}")

        elif args.action == "link-challenge":
            identity = _identity_mod().IdentityResolver()
            code = identity.create_challenge(args.user)
            print(f"Codigo generado para {args.user}: {code}")
            print("TTL: 5 minutos. En la otra plataforma ejecuta:")
            print(f"  hermes rbac link-confirm <plataforma>:<user_id> {code} "
                  f"--keep-memory a|b")

        elif args.action == "link-confirm":
            identity = _identity_mod().IdentityResolver()
            codes = identity._read_links()
            entry = codes.get(args.code)
            if entry is None:
                print("deny: codigo invalido o ya usado")
                raise SystemExit(1)
            origin_key = entry["user_key"]
            key_map = {"a": origin_key, "b": args.user}
            keep = key_map[args.keep_memory]
            try:
                person_id = identity.confirm_challenge(args.code, args.user, keep)
            except _identity_mod().IdentityError as e:
                print(f"deny: {e}")
                raise SystemExit(1)
            other = origin_key if keep != origin_key else args.user
            print(f"ok: vinculado a persona '{person_id}'")
            print(f"  canonical (roles + memoria): {keep}")
            print(f"  archivado (no se borra):    {other}")

        elif args.action == "unlink":
            identity = _identity_mod().IdentityResolver()
            if not identity.unlink(args.user):
                print(f"'{args.user}' no estaba vinculado")
                return
            print(f"ok: '{args.user}' desvinculado")

    return setup, handler


def make_slash(resolver_getter, identity_getter=None):
    """Fabrica el handler de /rbac in-session (issue #8). Solo lectura."""

    def slash_handler(raw_args: str, **_kw) -> str:
        resolver = resolver_getter()
        resolver.maybe_reload()
        parts = (raw_args or "").split()
        action = parts[0] if parts else "help"

        if action == "whoami":
            # El framework de slash commands no pasa el contexto del evento
            # al handler (solo raw_args), asi que no podemos saber quien
            # pregunta. Limitacion conocida: dirigir al usuario al agente,
            # que SI ve la identidad de sesion y puede consultar el RBAC.
            return ("No puedo saber quien sos desde un slash command "
                    "(el framework no pasa el contexto de sesion). "
                    "Preguntale al agente directamente: \"que permisos RBAC "
                    "tengo?\" — el si ve tu identidad y consulta tus roles. "
                    "O usa `/rbac user <platform>:<id>` si conoces tu key.")

        if action == "roles":
            desc = resolver.describe_roles()
            if not desc:
                return "No hay roles definidos."
            lines = []
            for name, info in sorted(desc.items()):
                lines.append(f"**{name}**: toolsets={', '.join(info['toolsets']) or '-'}")
            return "Roles:\n" + "\n".join(lines)

        if action == "user" and len(parts) > 1:
            perms = resolver.effective(parts[1])
            if perms is None:
                return f"{parts[1]}: sin acceso."
            return (f"**{parts[1]}** — roles: {', '.join(sorted(perms.roles))}; "
                    f"toolsets: {', '.join(sorted(perms.toolsets)) or 'ninguno'}")

        if action == "identities":
            if identity_getter is None:
                return "Identidades no disponibles."
            identity = identity_getter()
            identity.maybe_reload()
            persons = identity.describe_persons()
            if not persons:
                return ("No hay personas vinculadas todavia.\n\n"
                        "Para vincular dos cuentas tuyas (ej. Discord + Telegram):\n"
                        "1. En la plataforma A: `hermes rbac link-challenge "
                        "<platform>:<user_id>` — genera un codigo LINK-XXXXXX "
                        "(TTL 5 min).\n"
                        "2. En la plataforma B: `hermes rbac link-confirm "
                        "<platform>:<user_id> LINK-XXXXXX --keep-memory a|b` — "
                        "vos elegis que memoria conservar; la otra queda "
                        "archivada (no se borra).\n\n"
                        "Desde entonces ambas cuentas comparten roles y memoria "
                        "(un solo bank de Hindsight).")
            lines = []
            for pid, p in persons.items():
                keys = ", ".join(p["identities"])
                lines.append(f"**{pid}** — canonical: `{p['canonical']}` "
                             f"({keys})")
            return "Personas vinculadas:\n" + "\n".join(lines)

        return ("`/rbac whoami` — tu identidad\n"
                "`/rbac roles` — lista de roles\n"
                "`/rbac user <key>` — detalle de usuario\n"
                "`/rbac identities` — personas vinculadas + como vincular\n"
                "Mutaciones: solo por CLI (`hermes rbac ...`).")

    return slash_handler
