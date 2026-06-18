"""Client HTTP responsable : rate-limiting, retry et cache disque.

Centralise tous les accès réseau du pipeline pour garantir un usage respectueux
des serveurs externes (section 8 du sujet) : un délai est appliqué entre chaque
appel réseau réel, et les réponses JSON sont mises en cache sur disque afin
d'éviter de réinterroger une ressource déjà téléchargée.
"""

import json
import time
from pathlib import Path
from typing import Optional

import requests

from . import config

# Horodatage du dernier appel réseau, pour faire respecter REQUEST_DELAY.
_last_request_ts = 0.0


def _respect_delay() -> None:
    """Bloque le temps nécessaire pour espacer les appels de REQUEST_DELAY."""
    global _last_request_ts
    elapsed = time.monotonic() - _last_request_ts
    wait = config.REQUEST_DELAY - elapsed
    if wait > 0:
        time.sleep(wait)
    _last_request_ts = time.monotonic()


def _read_cache(cache_path: Optional[Path]) -> Optional[dict]:
    if cache_path is None or not cache_path.exists():
        return None
    try:
        with cache_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        # Cache corrompu : on l'ignore et on re-téléchargera.
        return None


def _write_cache(cache_path: Optional[Path], data: dict) -> None:
    if cache_path is None:
        return
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except OSError:
        # L'échec d'écriture du cache ne doit pas casser le pipeline.
        pass


def get_json(url: str, cache_path: Optional[Path] = None) -> Optional[dict]:
    """Récupère une ressource JSON, avec cache disque et accès responsable.

    Renvoie le dict JSON, ou ``None`` en cas d'échec définitif (réseau, HTTP,
    JSON invalide). Ne lève pas : le pipeline doit pouvoir continuer.
    """
    cached = _read_cache(cache_path)
    if cached is not None:
        return cached

    headers = {"User-Agent": config.USER_AGENT}
    for attempt in range(1, config.MAX_RETRIES + 1):
        _respect_delay()
        try:
            resp = requests.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            if attempt == config.MAX_RETRIES:
                print(f"  [http] échec réseau pour {url} : {exc}")
                return None
            time.sleep(config.REQUEST_DELAY * attempt)
            continue

        # 429 / 5xx : on retente avec un backoff.
        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt == config.MAX_RETRIES:
                print(f"  [http] {resp.status_code} persistant pour {url}")
                return None
            time.sleep(config.REQUEST_DELAY * attempt)
            continue

        try:
            resp.raise_for_status()
            data = resp.json()
        except (requests.HTTPError, ValueError) as exc:
            print(f"  [http] réponse invalide pour {url} : {exc}")
            return None

        _write_cache(cache_path, data)
        return data

    return None
