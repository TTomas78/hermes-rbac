"""Tests unitarios del resolver de identidades (Fase 3a hermes-rbac).

Criterio de done: resolve (vinculado/no vinculado), hot-reload por mtime,
link/unlink mutan identities.yaml, challenge OTP un solo uso + TTL.
"""

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest
import yaml

# El directorio del plugin se llama "hermes-rbac" (guion, no importable
# como paquete). Cargamos identity.py directamente por ruta.
_spec = importlib.util.spec_from_file_location(
    "identity", Path(__file__).resolve().parent.parent / "identity.py")
identity = importlib.util.module_from_spec(_spec)
sys.modules["identity"] = identity
_spec.loader.exec_module(identity)

IdentityResolver = identity.IdentityResolver
IdentityError = identity.IdentityError


def make_resolver(tmp_path, persons: dict) -> IdentityResolver:
    config = tmp_path / "identities.yaml"
    config.write_text(yaml.safe_dump({"persons": persons}), encoding="utf-8")
    links = tmp_path / "links.json"
    return IdentityResolver(config_path=config, links_path=links)


TOMAS = {
    "canonical": "discord:281593411675357184",
    "identities": ["discord:281593411675357184", "telegram:8422873335"],
}


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------

def test_resolve_canonical_devuelve_la_misma(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    assert r.resolve("discord:281593411675357184") == "discord:281593411675357184"


def test_resolve_no_canonica_devuelve_canonica(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    assert r.resolve("telegram:8422873335") == "discord:281593411675357184"


def test_resolve_desconocida_devuelve_la_misma_key(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    assert r.resolve("slack:U999") == "slack:U999"


def test_resolve_sin_archivo_devuelve_la_misma_key(tmp_path):
    r = IdentityResolver(config_path=tmp_path / "no-existe.yaml",
                         links_path=tmp_path / "links.json")
    assert r.resolve("discord:123") == "discord:123"
    assert r.load_error is None


def test_config_invalida_no_rompe_consultas(tmp_path):
    # Una identidad en dos personas = config invalida; consultas siguen
    # funcionando con el estado anterior (vacio).
    config = tmp_path / "identities.yaml"
    config.write_text(yaml.safe_dump({"persons": {
        "p1": {"canonical": "discord:1", "identities": ["discord:1"]},
        "p2": {"canonical": "discord:1", "identities": ["discord:1", "tg:2"]},
    }}), encoding="utf-8")
    r = IdentityResolver(config_path=config, links_path=tmp_path / "links.json")
    assert r.load_error is not None
    assert r.resolve("tg:2") == "tg:2"


# ---------------------------------------------------------------------------
# hot-reload
# ---------------------------------------------------------------------------

def test_hot_reload_detecta_cambios(tmp_path):
    config = tmp_path / "identities.yaml"
    config.write_text(yaml.safe_dump({"persons": {"tomas": TOMAS}}),
                      encoding="utf-8")
    r = IdentityResolver(config_path=config, links_path=tmp_path / "links.json")
    assert r.resolve("slack:U1") == "slack:U1"
    # Agregamos slack a tomas y forzamos mtime distinto.
    persons = {"tomas": {"canonical": TOMAS["canonical"],
                         "identities": TOMAS["identities"] + ["slack:U1"]}}
    config.write_text(yaml.safe_dump({"persons": persons}), encoding="utf-8")
    import os
    os.utime(config, (time.time() + 2, time.time() + 2))
    r.maybe_reload()
    assert r.resolve("slack:U1") == "discord:281593411675357184"


# ---------------------------------------------------------------------------
# link / unlink directo
# ---------------------------------------------------------------------------

def test_link_crea_persona_nueva(tmp_path):
    r = make_resolver(tmp_path, {})
    pid = r.link("discord:1", "telegram:2", keep="discord:1")
    assert r.resolve("telegram:2") == "discord:1"
    assert set(r.identities_for("discord:1")) == {"discord:1", "telegram:2"}
    assert pid in r.describe_persons()
    # Persistido en disco
    data = yaml.safe_load((tmp_path / "identities.yaml").read_text())
    assert pid in data["persons"]


def test_link_keep_elije_canonica(tmp_path):
    r = make_resolver(tmp_path, {})
    r.link("discord:1", "telegram:2", keep="telegram:2")
    assert r.resolve("discord:1") == "telegram:2"


def test_link_a_persona_existente(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    r.link("discord:281593411675357184", "slack:U777", keep="discord:281593411675357184")
    assert r.resolve("slack:U777") == "discord:281593411675357184"
    assert len(r.identities_for("telegram:8422873335")) == 3


def test_link_ya_vinculadas_falla(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    with pytest.raises(IdentityError):
        r.link("discord:281593411675357184", "telegram:8422873335",
               keep="discord:281593411675357184")


def test_link_identidad_de_otra_persona_falla(tmp_path):
    r = make_resolver(tmp_path, {
        "tomas": TOMAS,
        "otro": {"canonical": "slack:U1", "identities": ["slack:U1"]},
    })
    with pytest.raises(IdentityError):
        r.link("discord:9", "slack:U1", keep="discord:9")


def test_unlink_desvincula_y_persona_sobrevive(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    assert r.unlink("telegram:8422873335") is True
    assert r.resolve("telegram:8422873335") == "telegram:8422873335"
    assert r.resolve("discord:281593411675357184") == "discord:281593411675357184"


def test_unlink_canonica_reelege_canonical(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    r.unlink("discord:281593411675357184")
    # La persona sigue con telegram como unica identidad y canonical.
    assert r.resolve("telegram:8422873335") == "telegram:8422873335"
    persons = r.describe_persons()
    assert persons["tomas"]["canonical"] == "telegram:8422873335"


def test_unlink_no_vinculada_devuelve_false(tmp_path):
    r = make_resolver(tmp_path, {"tomas": TOMAS})
    assert r.unlink("slack:U999") is False


# ---------------------------------------------------------------------------
# Challenge OTP
# ---------------------------------------------------------------------------

def test_challenge_formato_y_un_solo_uso(tmp_path):
    r = make_resolver(tmp_path, {})
    code = r.create_challenge("discord:1")
    assert code.startswith("LINK-") and len(code) == 11
    pid = r.confirm_challenge(code, "telegram:2", keep="discord:1")
    assert r.resolve("telegram:2") == "discord:1"
    with pytest.raises(IdentityError, match="invalido"):
        r.confirm_challenge(code, "slack:3", keep="discord:1")


def test_challenge_expirado_falla(tmp_path):
    r = make_resolver(tmp_path, {})
    code = r.create_challenge("discord:1", ttl=0)
    time.sleep(0.01)
    with pytest.raises(IdentityError, match="expirado"):
        r.confirm_challenge(code, "telegram:2", keep="discord:1")


def test_challenge_autolink_falla(tmp_path):
    r = make_resolver(tmp_path, {})
    code = r.create_challenge("discord:1")
    with pytest.raises(IdentityError, match="vos mismo"):
        r.confirm_challenge(code, "discord:1", keep="discord:1")


def test_challenge_persistido_en_disco(tmp_path):
    config = tmp_path / "identities.yaml"
    config.write_text(yaml.safe_dump({"persons": {}}), encoding="utf-8")
    links = tmp_path / "links.json"
    r1 = IdentityResolver(config_path=config, links_path=links)
    code = r1.create_challenge("discord:1")
    # Otro proceso (otra instancia) lee el mismo links.json.
    r2 = IdentityResolver(config_path=config, links_path=links)
    r2.confirm_challenge(code, "telegram:2", keep="telegram:2")
    assert r2.resolve("discord:1") == "telegram:2"
