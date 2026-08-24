"""Audit log JSONL para hermes-rbac (issue #10).

Una linea JSON por decision, con rotacion por tamano.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_PATH = Path.home() / ".hermes" / "plugins" / "hermes-rbac" / "audit.jsonl"
MAX_BYTES = 10 * 1024 * 1024  # 10 MB -> rota a audit.jsonl.1

_lock = threading.Lock()


class AuditLog:
    def __init__(self, path: Optional[Path] = None):
        self._path = Path(path) if path else DEFAULT_AUDIT_PATH

    def log(self, event: str, user: str, decision: str,
            tool: Optional[str] = None, roles: Optional[list] = None,
            reason: Optional[str] = None, **extra: Any) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            "user": user,
            "decision": decision,
        }
        if tool is not None:
            entry["tool"] = tool
        if roles is not None:
            entry["roles"] = sorted(roles)
        if reason:
            entry["reason"] = reason
        entry.update(extra)
        line = json.dumps(entry, ensure_ascii=False)
        with _lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                if self._path.exists() and self._path.stat().st_size > MAX_BYTES:
                    self._path.replace(self._path.with_suffix(".jsonl.1"))
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError as e:
                logger.warning("hermes-rbac: no se pudo escribir audit log: %s", e)
