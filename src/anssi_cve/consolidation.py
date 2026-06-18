"""Étape 4 : consolidation des données enrichies dans un DataFrame pandas."""

from typing import Optional

import pandas as pd

from .enrichment import UNAVAILABLE

# Colonnes du DataFrame consolidé (ordre du livrable CSV).
COLUMNS = [
    "id_anssi",
    "titre_anssi",
    "type_bulletin",
    "date_publication",
    "cve_id",
    "score_cvss",
    "base_severity",
    "type_cwe",
    "score_epss",
    "lien_bulletin",
    "description",
    "editeur",
    "produit",
    "versions_affectees",
]


def severity_from_cvss(score: Optional[float]) -> str:
    """Traduit un score CVSS (0-10) en gravité (barème du sujet)."""
    if score is None:
        return UNAVAILABLE
    if score < 4:
        return "Faible"
    if score < 7:
        return "Moyenne"
    if score < 9:
        return "Élevée"
    return "Critique"


def _format_affected(affected: list[dict]) -> tuple[str, str, str]:
    """Aplatit la liste des produits affectés en (éditeurs, produits, versions).

    Plusieurs produits possibles par CVE : on concatène les valeurs distinctes
    avec ``" ; "`` pour conserver une ligne par couple (bulletin × CVE).
    """
    if not affected:
        return UNAVAILABLE, UNAVAILABLE, UNAVAILABLE

    def _join(values: list[str]) -> str:
        seen = [v for v in dict.fromkeys(values) if v and v != UNAVAILABLE]
        return " ; ".join(seen) if seen else UNAVAILABLE

    vendors = _join([a["vendor"] for a in affected])
    products = _join([a["product"] for a in affected])
    versions = _join([", ".join(a["versions"]) for a in affected if a["versions"]])
    return vendors, products, versions


def build_row(bulletin: dict, cve_id: str, mitre: dict, epss: Optional[float]) -> dict:
    """Construit une ligne consolidée pour un couple (bulletin × CVE)."""
    vendor, product, versions = _format_affected(mitre["affected"])
    return {
        "id_anssi": bulletin["id_anssi"],
        "titre_anssi": bulletin["titre_anssi"],
        "type_bulletin": bulletin["type_bulletin"],
        "date_publication": bulletin["date_publication"],
        "cve_id": cve_id,
        "score_cvss": mitre["cvss_score"],
        "base_severity": severity_from_cvss(mitre["cvss_score"]),
        "type_cwe": mitre["cwe"],
        "score_epss": epss,
        "lien_bulletin": bulletin["lien_bulletin"],
        "description": mitre["description"],
        "editeur": vendor,
        "produit": product,
        "versions_affectees": versions,
    }


def build_dataframe(rows: list[dict]) -> pd.DataFrame:
    """Assemble les lignes consolidées en DataFrame avec colonnes ordonnées."""
    return pd.DataFrame(rows, columns=COLUMNS)
