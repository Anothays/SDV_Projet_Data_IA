"""Interface d'administration Django — consultation rapide des données.

Offre gratuitement recherche, filtres et pagination sur les CVE et bulletins
(`/admin/`). Pratique pour explorer/valider l'import sans écrire de vue.
"""

from django.contrib import admin

from .models import Bulletin, Cve


@admin.register(Cve)
class CveAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "base_severity", "score_cvss", "score_epss", "editeur", "produit_court")
    list_filter = ("base_severity",)
    search_fields = ("cve_id", "description", "editeur", "produit")
    ordering = ("cve_id",)

    @admin.display(description="Produit(s)")
    def produit_court(self, obj):
        """Tronque le champ produit (parfois très long) pour la liste."""
        return (obj.produit or "")[:80]


@admin.register(Bulletin)
class BulletinAdmin(admin.ModelAdmin):
    list_display = ("id_anssi", "type_bulletin", "date_publication", "titre_anssi")
    list_filter = ("type_bulletin",)
    search_fields = ("id_anssi", "titre_anssi")
    date_hierarchy = "date_publication"
    ordering = ("-date_publication",)
    filter_horizontal = ("cves",)
