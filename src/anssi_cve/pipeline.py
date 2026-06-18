"""Orchestration end-to-end des étapes 1 à 4 → écriture du CSV consolidé."""

from typing import Optional

import pandas as pd

from . import config
from .consolidation import build_dataframe, build_row
from .cve_extraction import extract_cves, fetch_bulletin_json
from .enrichment import enrich_epss, enrich_mitre
from .local_source import fetch_bulletins


def run(output_csv=config.OUTPUT_CSV, years=config.DEFAULT_YEARS) -> pd.DataFrame:
    """Exécute le pipeline complet et écrit le DataFrame consolidé en CSV.

    ``years`` borne le périmètre (cf. ``config.DEFAULT_YEARS``) ; ``None`` = tout.
    """
    print("[1/4] Lecture des bulletins ANSSI (dump local data/Avis + data/alertes)...")
    bulletins = fetch_bulletins(years=years)
    print(f"      {len(bulletins)} bulletins chargés (années={years}).")

    # Caches d'enrichissement en mémoire : une CVE partagée par plusieurs
    # bulletins n'est interrogée qu'une seule fois.
    mitre_cache: dict[str, dict] = {}
    epss_cache: dict[str, Optional[float]] = {}

    rows: list[dict] = []
    print("[2-3/4] Extraction des CVE et enrichissement (MITRE + EPSS)...")
    for idx, bulletin in enumerate(bulletins, start=1):
        bulletin_json = fetch_bulletin_json(bulletin)
        if bulletin_json is None:
            print(f"  ({idx}/{len(bulletins)}) {bulletin['id_anssi']} : JSON indisponible, ignoré.")
            continue

        cve_ids = extract_cves(bulletin_json)
        print(f"  ({idx}/{len(bulletins)}) {bulletin['id_anssi']} : {len(cve_ids)} CVE.")

        for cve_id in cve_ids:
            if cve_id not in mitre_cache:
                mitre_cache[cve_id] = enrich_mitre(cve_id)
                epss_cache[cve_id] = enrich_epss(cve_id)
            rows.append(build_row(bulletin, cve_id, mitre_cache[cve_id], epss_cache[cve_id]))

    print("[4/4] Consolidation et écriture du CSV...")
    df = build_dataframe(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    print(
        f"      {len(df)} lignes / {df['cve_id'].nunique()} CVE uniques "
        f"écrites dans {output_csv}"
    )
    return df


if __name__ == "__main__":
    run()
