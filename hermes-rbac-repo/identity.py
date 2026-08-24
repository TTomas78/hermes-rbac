"""Identidades unificadas cross-plataforma para hermes-rbac (Fase 3a).

Una "persona" agrupa varias identidades ``platform:user_id`` del mismo humano.
La identidad ``canonical`` es la que se usa para:

- RBAC: los roles se buscan por la key canonica en roles.yaml.
- Memoria: el dispatch muta ``event.source.user_id`` al canonical, asi el
  template ``hermes-{profile}-{user}`` de Hindsight apunta a UN solo bank.

Vinculacion self-service por challenge (OTP):

1. En plataforma A: ``hermes rbac link-challenge <key_a>`` genera LINK-XXXXXX
   (un solo uso, TTL 5 min, persistido en links.json).
2. En plataforma B: ``hermes rbac link-confirm <key_b> LINK-XXXXXX
   --keep-memory a|b`` valida el codigo y vincula. El USUARIO elige que
   memoria conservar: la del canal elegido pasa a ser la canonical; la otra
   queda archivada (huerfana, no se borra — reversible con unlink).

Sin dependencias externas (yaml + json stdlib).
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).resolve().parent
DEFAULT_IDENTITIES_PATH = _PLUGIN_DIR / "identities.yaml"
DEFAULT_LINKS_PATH = _PLUGIN_DIR / "links.json"

CHALLENGE_TTL_SECONDS = 300  # 5 minutos
CHALLENGE_PREFIX = "LINK-"


class IdentityError(Exception):
    """Error de operacion de identidades (link invalido, conflicto, etc.)."""


class IdentityResolver:
    """Resuelve platform:user_id -> identidad canonica. Hot-reload por mtime."""

    def __init__(self, config_path: Optional[Path] = None,
                 links_path: Optional[Path] = None):
        self._config_path = Path(config_path) if config_path else DEFAULT_IDENTITIES_PATH
        self._links_path = Path(links_path) if links_path else DEFAULT_LINKS_PATH
        # mapa identidad -> person_id
        self._by_identity: Dict[str, str] = {}
        # person_id -> {"canonical": str, "identities": [str]}
        self._persons: Dict[str, Dict[str, Any]] = {}
        self._load_error: Optional[str] = None
        self._mtime: float = 0.0
        self.reload()

    # ------------------------------------------------------------------
    # Carga / hot-reload
    # ------------------------------------------------------------------

    def reload(self) -> bool:
        """(Re)carga identities.yaml. Ausencia del archivo = sin personas."""
        try:
            if not self._config_path.exists():
                self._by_identity = {}
                self._persons = {}
                self._load_error = None
                self._mtime = 0.0
                return True
            raw = yaml.safe_load(self._config_path.read_text(encoding="utf-8")) or {}
            persons = raw.get("persons") or {}
            by_identity: Dict[str, str] = {}
            parsed: Dict[str, Dict[str, Any]] = {}
            for person_id, data in persons.items():
                identities = list((data or {}).get("identities") or [])
                canonical = (data or {}).get("canonical") or (identities[0] if identities else None)
                if not identities or canonical not in identities:
                    raise IdentityError(
                        f"persona '{person_id}': canonical debe ser una de sus identities")
                for key in identities:
                    if key in by_identity:
                        raise IdentityError(
                            f"identidad '{key}' aparece en dos personas "
                            f"('{by_identity[key]}' y '{person_id}')")
                    by_identity[key] = person_id
                parsed[str(person_id)] = {"canonical": canonical,
                                          "identities": identities}
            self._by_identity = by_identity
            self._persons = parsed
            self._load_error = None
            self._mtime = self._config_path.stat().st_mtime
            return True
        except Exception as e:
            self._load_error = str(e)
            logger.error("hermes-rbac identity: error cargando %s: %s",
                         self._config_path, e)
            return False

    def maybe_reload(self) -> bool:
        """Recarga solo si el archivo cambio (pattern de RoleResolver)."""
        try:
            mtime = self._config_path.stat().st_mtime
        except OSError:
            mtime = 0.0
        if mtime != self._mtime:
            return self.reload()
        return self._load_error is None

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------

    def resolve(self, user_key: str) -> str:
        """Devuelve la key canonica para user_key (o la misma si no esta vinculada)."""
        person_id = self._by_identity.get(user_key)
        if person_id is None:
            return user_key
        return self._persons[person_id]["canonical"]

    def person_for(self, user_key: str) -> Optional[str]:
        return self._by_identity.get(user_key)

    def identities_for(self, user_key: str) -> List[str]:
        person_id = self._by_identity.get(user_key)
        if person_id is None:
            return [user_key]
        return list(self._persons[person_id]["identities"])

    def describe_persons(self) -> Dict[str, Dict[str, Any]]:
        return {pid: dict(p) for pid, p in self._persons.items()}

    # ------------------------------------------------------------------
    # Mutaciones (link / unlink)
    # ------------------------------------------------------------------

    def _save(self) -> None:
        data = {"persons": {pid: {"canonical": p["canonical"],
                                  "identities": p["identities"]}
                            for pid, p in self._persons.items()}}
        self._config_path.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
            encoding="utf-8")
        self.reload()

    def link(self, key_a: str, key_b: str, keep: str) -> str:
        """Vincula dos identidades en una persona. ``keep`` = key canonica.

        Devuelve el person_id. Si key_a ya tiene persona, agrega key_b a ella.
        """
        if keep not in (key_a, key_b):
            raise IdentityError(f"keep debe ser '{key_a}' o '{key_b}'")
        person_a = self._by_identity.get(key_a)
        person_b = self._by_identity.get(key_b)
        if person_a is not None and person_b is not None:
            if person_a == person_b:
                raise IdentityError("esas identidades ya estan vinculadas")
            raise IdentityError(
                f"'{key_b}' ya pertenece a la persona '{person_b}'; "
                "hace unlink primero")
        if person_b is not None:
            raise IdentityError(
                f"'{key_b}' ya pertenece a la persona '{person_b}'; "
                "hace unlink primero")

        if person_a is None:
            person_id = key_a.split(":", 1)[0] + "-" + secrets.token_hex(3)
            self._persons[person_id] = {"canonical": keep,
                                        "identities": [key_a, key_b]}
            self._by_identity[key_a] = person_id
            self._by_identity[key_b] = person_id
        else:
            person_id = person_a
            person = self._persons[person_id]
            person["identities"].append(key_b)
            person["canonical"] = keep
            self._by_identity[key_b] = person_id

        self._save()
        logger.info("hermes-rbac identity: link %s <-> %s (canonical=%s, person=%s)",
                    key_a, key_b, keep, person_id)
        return person_id

    def unlink(self, user_key: str) -> bool:
        """Desvincula una identidad de su persona. True si estaba vinculada."""
        person_id = self._by_identity.get(user_key)
        if person_id is None:
            return False
        person = self._persons[person_id]
        person["identities"].remove(user_key)
        del self._by_identity[user_key]
        if not person["identities"]:
            del self._persons[person_id]
        else:
            if person["canonical"] == user_key:
                person["canonical"] = person["identities"][0]
        self._save()
        logger.info("hermes-rbac identity: unlink %s (person=%s)", user_key, person_id)
        return True

    # ------------------------------------------------------------------
    # Challenge OTP (links.json — compartido entre procesos CLI/gateway)
    # ------------------------------------------------------------------

    def _read_links(self) -> Dict[str, Any]:
        try:
            return json.loads(self._links_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write_links(self, data: Dict[str, Any]) -> None:
        self._links_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def create_challenge(self, user_key: str,
                         ttl: int = CHALLENGE_TTL_SECONDS) -> str:
        """Genera un codigo LINK-XXXXXX de un solo uso para user_key."""
        codes = self._read_links()
        # Poda de expirados
        now = time.time()
        codes = {c: v for c, v in codes.items() if v.get("expires", 0) > now}
        code = CHALLENGE_PREFIX + "".join(
            secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
        codes[code] = {"user_key": user_key, "expires": now + ttl}
        self._write_links(codes)
        return code

    def confirm_challenge(self, code: str, user_key: str, keep: str) -> str:
        """Valida el codigo y vincula user_key con la identidad origen.

        ``keep`` es la key cuya memoria se conserva (decision del usuario).
        Devuelve person_id. El codigo se consume siempre (un solo uso).
        """
        codes = self._read_links()
        entry = codes.pop(code, None)
        self._write_links(codes)
        if entry is None:
            raise IdentityError("codigo invalido o ya usado")
        if entry.get("expires", 0) < time.time():
            raise IdentityError("codigo expirado (TTL 5 min); genera uno nuevo")
        origin_key = entry["user_key"]
        if origin_key == user_key:
            raise IdentityError("no podes vincularte con vos mismo")
        return self.link(origin_key, user_key, keep)
