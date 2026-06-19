"""Pipeline d'extraction et d'enrichissement des bulletins de sécurité ANSSI.

Étapes 1 à 4 du TD : lecture des bulletins CERT-FR (avis + alertes) depuis le
dump local fourni, identification des CVE référencées, enrichissement via les
API MITRE et EPSS (dump local puis réseau en repli), puis consolidation dans un
DataFrame pandas exporté en CSV.
"""

__all__ = ["config", "http_client", "local_source", "cve_extraction", "enrichment", "consolidation", "pipeline"]
