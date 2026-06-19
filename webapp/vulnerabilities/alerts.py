"""Alertes critiques (étape 7 du notebook portée en web).

Critère de déclenchement identique au notebook : ``CVSS ≥ 9`` **OU** ``EPSS ≥ 0.5``
(le OU capture à la fois les vulnérabilités très graves et celles très exploitées).
``build_alert_email`` reprend le gabarit de sujet/corps du notebook. L'envoi SMTP
reste hors périmètre : on n'affiche qu'un aperçu.
"""

from django.db.models import Q

from .models import Cve

CVSS_SEUIL = 9.0   # gravité « Critique » du barème CVSS
EPSS_SEUIL = 0.5   # probabilité d'exploitation majoritaire


def alert_cves():
    """CVE déclenchant une alerte, triées par priorité (EPSS puis CVSS décroissants)."""
    return (
        Cve.objects.filter(Q(score_cvss__gte=CVSS_SEUIL) | Q(score_epss__gte=EPSS_SEUIL))
        .prefetch_related("bulletins")
        .order_by("-score_epss", "-score_cvss")
    )


def _produit_court(cve: Cve) -> str:
    """1er produit affecté, tronqué (le champ produit peut être très long)."""
    premier = (cve.produit or "").split(" ; ")[0].strip()
    return (premier[:60] or "produit non précisé")


def build_alert_email(cve: Cve, bulletin=None) -> tuple[str, str]:
    """Construit (sujet, corps) d'un mail d'alerte pour une CVE critique."""
    bulletin = bulletin or cve.bulletins.first()
    id_anssi = bulletin.id_anssi if bulletin else "—"
    lien = bulletin.lien_bulletin if bulletin else ""
    cvss = "N/A" if cve.score_cvss is None else f"{cve.score_cvss:.1f}"
    epss = "N/A" if cve.score_epss is None else f"{cve.score_epss:.1%}"

    sujet = f"[Alerte sécurité] {cve.cve_id} — {cve.base_severity} sur {_produit_court(cve)}"
    corps = f"""Bonjour,

Une vulnérabilité critique a été identifiée concernant un produit que vous suivez.

  • CVE          : {cve.cve_id}
  • Produit      : {cve.produit} ({cve.editeur})
  • Versions     : {cve.versions_affectees}
  • Gravité CVSS : {cvss} / 10 ({cve.base_severity})
  • Exploitation : probabilité EPSS {epss}
  • Type (CWE)   : {cve.type_cwe}
  • Bulletin     : {id_anssi} — {lien}

Description : {str(cve.description)[:400]}

Action recommandée : appliquer sans délai les correctifs de l'éditeur et vérifier
l'exposition de vos systèmes.

— Veille automatisée CVE / CERT-FR"""
    return sujet, corps
