"""Pipeline d'extraction et d'enrichissement des bulletins de sécurité ANSSI.

Étapes 1 à 4 du TD : extraction des flux RSS CERT-FR (avis + alertes),
identification des CVE référencées, enrichissement via les API MITRE et EPSS,
puis consolidation dans un DataFrame pandas exporté en CSV.
"""

__all__ = ["config", "http_client", "rss", "cve_extraction", "enrichment", "consolidation", "pipeline"]
