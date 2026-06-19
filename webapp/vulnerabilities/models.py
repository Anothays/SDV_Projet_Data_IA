"""Modèles de la web app : schéma normalisé du `consolidated.csv`.

Le CSV livré contient une ligne par couple (bulletin × CVE). L'enrichissement
(CVSS, CWE, EPSS, éditeur, produit, description) est **identique pour un même
`cve_id`** quel que soit le bulletin qui le cite → on normalise en deux tables
(`Bulletin`, `Cve`) reliées par un Many-to-Many, ce qui évite de dupliquer
~90 k descriptions et permet de répondre à « cette CVE apparaît dans N bulletins ».
"""

from django.db import models

# Valeur sentinelle du pipeline amont pour un enrichissement absent (cf.
# anssi_cve.enrichment.UNAVAILABLE). Conservée telle quelle côté texte pour
# distinguer « non renseigné » d'une vraie valeur.
UNAVAILABLE = "Non disponible"

# Ordre métier des gravités (du barème CVSS du sujet), pour tris et filtres.
SEVERITY_ORDER = ["Critique", "Élevée", "Moyenne", "Faible", UNAVAILABLE]


class Cve(models.Model):
    """Une vulnérabilité (CVE) enrichie MITRE + EPSS — niveau « vulnérabilité »."""

    cve_id = models.CharField("Identifiant CVE", max_length=32, unique=True, db_index=True)
    score_cvss = models.FloatField("Score CVSS", null=True, blank=True)
    base_severity = models.CharField("Gravité", max_length=20, db_index=True)
    type_cwe = models.CharField("Type CWE", max_length=32)
    score_epss = models.FloatField("Score EPSS", null=True, blank=True, db_index=True)
    description = models.TextField("Description", blank=True)
    editeur = models.CharField("Éditeur", max_length=255, db_index=True)
    produit = models.TextField("Produit(s)", blank=True)
    versions_affectees = models.TextField("Versions affectées", blank=True)

    class Meta:
        verbose_name = "CVE"
        verbose_name_plural = "CVE"
        ordering = ["cve_id"]

    def __str__(self) -> str:
        return self.cve_id

    @property
    def is_alert(self) -> bool:
        """Vrai si la CVE déclenche une alerte (CVSS ≥ 9 OU EPSS ≥ 0.5)."""
        return (self.score_cvss is not None and self.score_cvss >= 9.0) or (
            self.score_epss is not None and self.score_epss >= 0.5
        )


class Bulletin(models.Model):
    """Un bulletin CERT-FR (avis ou alerte) — niveau « publication »."""

    id_anssi = models.CharField("Identifiant ANSSI", max_length=32, unique=True, db_index=True)
    titre_anssi = models.CharField("Titre", max_length=255)
    type_bulletin = models.CharField("Type", max_length=16, db_index=True)
    date_publication = models.DateTimeField("Date de publication", null=True, blank=True, db_index=True)
    lien_bulletin = models.URLField("Lien", max_length=255, blank=True)
    cves = models.ManyToManyField(Cve, related_name="bulletins", verbose_name="CVE citées")

    class Meta:
        verbose_name = "bulletin"
        verbose_name_plural = "bulletins"
        ordering = ["-date_publication", "id_anssi"]

    def __str__(self) -> str:
        return self.id_anssi
