"""Registry session_id -> user_key para hermes-rbac.

pre_gateway_dispatch ve el usuario; pre_tool_call solo recibe session_id.
Este modulo los conecta: el dispatch registra la sesion con TTL y el gate
de tools la consulta. TTL evita crecimiento infinito y re-uso de ids viejos.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional, Tuple

TTL_SECONDS = 24 * 3600  # sesiones de gateway duran menos que esto en la practica

_lock = threading.Lock()
_sessions: Dict[str, Tuple[str, float]] = {}


def register_session(session_id: str, user_key: str) -> None:
    if not session_id or not user_key:
        return
    with _lock:
        _sessions[session_id] = (user_key, time.monotonic())
        _maybe_prune()


def user_for_session(session_id: str) -> Optional[str]:
    if not session_id:
        return None
    with _lock:
        entry = _sessions.get(session_id)
        if entry is None:
            return None
        user_key, ts = entry
        if time.monotonic() - ts > TTL_SECONDS:
            del _sessions[session_id]
            return None
        return user_key


def _maybe_prune() -> None:
    """Poda lazy: solo cuando el mapa crece mucho."""
    if len(_sessions) < 1000:
        return
    now = time.monotonic()
    stale = [k for k, (_, ts) in _sessions.items() if now - ts > TTL_SECONDS]
    for k in stale:
        del _sessions[k]


def clear() -> None:
    with _lock:
        _sessions.clear()
