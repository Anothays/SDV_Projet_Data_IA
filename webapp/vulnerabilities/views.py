"""Vues de la web app : tableau de bord, listes filtrables, détails, alertes."""

import csv

from django.core.paginator import Paginator
from django.db.models import Q
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404, render

from .alerts import alert_cves, build_alert_email
from .charts import build_dashboard_charts
from .models import SEVERITY_ORDER, UNAVAILABLE, Bulletin, Cve

PAGE_SIZE = 25


def _querystring_excluding(request, *names: str) -> str:
    """Querystring courant sans les paramètres donnés (pagination, tri…)."""
    params = request.GET.copy()
    for name in names:
        params.pop(name, None)
    return params.urlencode()


def _resolve_sort(request, allowed_fields: set[str], default: str) -> str:
    """Valide le paramètre ``sort`` (``champ`` ou ``-champ``) contre une liste autorisée."""
    sort = request.GET.get("sort", default)
    if sort.lstrip("-") not in allowed_fields:
        sort = default
    return sort


def _published_years() -> list[int]:
    """Années de publication présentes en base (pour le filtre déroulant)."""
    dates = Bulletin.objects.exclude(date_publication=None).dates("date_publication", "year")
    return sorted({d.year for d in dates}, reverse=True)


def _editeurs() -> list[str]:
    """Valeurs distinctes d'éditeur présentes en base (pour le filtre déroulant)."""
    return list(
        Cve.objects.exclude(editeur="")
        .exclude(editeur=UNAVAILABLE)
        .order_by("editeur")
        .values_list("editeur", flat=True)
        .distinct()
    )


def dashboard(request):
    """Tableau de bord : indicateurs clés + graphiques Plotly (étape 5)."""
    total_cves = Cve.objects.count()
    n_critiques = Cve.objects.filter(base_severity="Critique").count()
    context = {
        "total_cves": total_cves,
        "total_bulletins": Bulletin.objects.count(),
        "n_critiques": n_critiques,
        "n_alertes": alert_cves().count(),
        "pct_critiques": round(100 * n_critiques / total_cves, 1) if total_cves else 0,
        "charts": build_dashboard_charts(),
    }
    return render(request, "vulnerabilities/dashboard.html", context)


def _filter_cves(request):
    """Applique les filtres de la liste CVE et renvoie ``(queryset, filters)``.

    Factorisé pour être partagé entre la liste HTML et l'export CSV (mêmes
    critères : recherche, gravité, éditeur, scores minimaux, année).
    """
    qs = Cve.objects.all()
    filters = {
        "q": request.GET.get("q", "").strip(),
        "severity": request.GET.get("severity", "").strip(),
        "editeur": request.GET.get("editeur", "").strip(),
        "cvss_min": request.GET.get("cvss_min", "").strip(),
        "epss_min": request.GET.get("epss_min", "").strip(),
        "annee": request.GET.get("annee", "").strip(),
    }

    if filters["q"]:
        qs = qs.filter(Q(cve_id__icontains=filters["q"]) | Q(description__icontains=filters["q"]))
    if filters["severity"]:
        qs = qs.filter(base_severity=filters["severity"])
    if filters["editeur"]:
        qs = qs.filter(editeur=filters["editeur"])
    if filters["cvss_min"]:
        try:
            qs = qs.filter(score_cvss__gte=float(filters["cvss_min"]))
        except ValueError:
            pass
    if filters["epss_min"]:
        try:
            qs = qs.filter(score_epss__gte=float(filters["epss_min"]))
        except ValueError:
            pass
    if filters["annee"]:
        try:
            qs = qs.filter(bulletins__date_publication__year=int(filters["annee"])).distinct()
        except ValueError:
            pass
    return qs, filters


def vulnerability_list(request):
    """Liste paginée et filtrable des CVE."""
    qs, filters = _filter_cves(request)
    sort = _resolve_sort(request, {"score_cvss", "score_epss"}, "-score_cvss")
    qs = qs.order_by(sort, "cve_id")
    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page"))
    context = {
        "page_obj": page,
        "filters": filters,
        "severities": SEVERITY_ORDER,
        "years": _published_years(),
        "editeurs": _editeurs(),
        "base_query": _querystring_excluding(request, "page"),
        "base_query_sort": _querystring_excluding(request, "page", "sort"),
        "sort": sort,
        "total": page.paginator.count,
    }
    return render(request, "vulnerabilities/vulnerability_list.html", context)


def vulnerability_detail(request, cve_id):
    """Détail d'une CVE et des bulletins qui la citent."""
    cve = get_object_or_404(Cve, cve_id=cve_id)
    context = {
        "cve": cve,
        "bulletins": cve.bulletins.all(),
        "is_alert": cve.is_alert,
    }
    return render(request, "vulnerabilities/vulnerability_detail.html", context)


def bulletin_list(request):
    """Liste paginée et filtrable des bulletins."""
    qs = Bulletin.objects.all()
    filters = {
        "q": request.GET.get("q", "").strip(),
        "type": request.GET.get("type", "").strip(),
        "annee": request.GET.get("annee", "").strip(),
    }
    if filters["q"]:
        qs = qs.filter(Q(id_anssi__icontains=filters["q"]) | Q(titre_anssi__icontains=filters["q"]))
    if filters["type"]:
        qs = qs.filter(type_bulletin=filters["type"])
    if filters["annee"]:
        try:
            qs = qs.filter(date_publication__year=int(filters["annee"]))
        except ValueError:
            pass

    sort = _resolve_sort(request, {"date_publication"}, "-date_publication")
    qs = qs.order_by(sort, "id_anssi")
    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page"))
    context = {
        "page_obj": page,
        "filters": filters,
        "types": list(Bulletin.objects.values_list("type_bulletin", flat=True).distinct()),
        "years": _published_years(),
        "base_query": _querystring_excluding(request, "page"),
        "base_query_sort": _querystring_excluding(request, "page", "sort"),
        "sort": sort,
        "total": page.paginator.count,
    }
    return render(request, "vulnerabilities/bulletin_list.html", context)


def bulletin_detail(request, id_anssi):
    """Détail d'un bulletin et des CVE qu'il référence."""
    bulletin = get_object_or_404(Bulletin, id_anssi=id_anssi)
    context = {
        "bulletin": bulletin,
        "cves": bulletin.cves.all().order_by("-score_cvss", "cve_id"),
    }
    return render(request, "vulnerabilities/bulletin_detail.html", context)


def _filtered_alert_cves(request):
    """Alertes (``alert_cves``) restreintes par éditeur / produit / année / type.

    C'est le cœur des « alertes sur mesure » du sujet : à partir du socle
    critique (CVSS ≥ 9 ou EPSS ≥ 0.5), l'utilisateur cible ses produits/éditeurs.
    Renvoie ``(queryset, filters)`` ; partagé par la page alertes et son export.
    """
    qs = alert_cves()
    filters = {
        "editeur": request.GET.get("editeur", "").strip(),
        "produit": request.GET.get("produit", "").strip(),
        "annee": request.GET.get("annee", "").strip(),
        "type": request.GET.get("type", "").strip(),
    }
    if filters["editeur"]:
        qs = qs.filter(editeur=filters["editeur"])
    if filters["produit"]:
        qs = qs.filter(produit__icontains=filters["produit"])
    if filters["annee"]:
        try:
            qs = qs.filter(bulletins__date_publication__year=int(filters["annee"])).distinct()
        except ValueError:
            pass
    if filters["type"]:
        qs = qs.filter(bulletins__type_bulletin=filters["type"]).distinct()
    return qs, filters


def alerts(request):
    """Alertes critiques (CVSS ≥ 9 ou EPSS ≥ 0.5), filtrables + aperçus d'email ciblés."""
    qs, filters = _filtered_alert_cves(request)
    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page"))

    # Aperçus email des 3 alertes les plus prioritaires de la sélection (étape 7) :
    # ils reflètent les filtres → l'email est « sur mesure ».
    previews = []
    for cve in qs[:3]:
        sujet, corps = build_alert_email(cve)
        previews.append({"sujet": sujet, "corps": corps})

    context = {
        "page_obj": page,
        "total": page.paginator.count,
        "previews": previews,
        "filters": filters,
        "editeurs": _editeurs(),
        "years": _published_years(),
        "types": list(Bulletin.objects.values_list("type_bulletin", flat=True).distinct()),
        "base_query": _querystring_excluding(request, "page"),
    }
    return render(request, "vulnerabilities/alerts.html", context)


# --------------------------------------------------------------------- export CSV

# Colonnes exportées (niveau CVE, cf. modèle Cve).
CVE_EXPORT_COLUMNS = [
    "cve_id", "score_cvss", "base_severity", "type_cwe", "score_epss",
    "editeur", "produit", "versions_affectees", "description",
]


class _Echo:
    """Buffer qui renvoie ce qu'on lui écrit (streaming CSV sans fichier tampon)."""

    def write(self, value):
        return value


def _stream_cves_csv(qs, filename: str) -> StreamingHttpResponse:
    """Streame un queryset de CVE en CSV téléchargeable (en-tête + lignes)."""
    writer = csv.writer(_Echo())

    def rows():
        yield writer.writerow(CVE_EXPORT_COLUMNS)
        # prefetch_related(None) : on coupe tout prefetch hérité (ex. alert_cves),
        # inutile pour un values_list et incompatible avec .iterator() sans chunk_size.
        for row in qs.prefetch_related(None).values_list(*CVE_EXPORT_COLUMNS).iterator():
            yield writer.writerow(row)

    response = StreamingHttpResponse(rows(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def export_cves(request) -> StreamingHttpResponse:
    """Export CSV de la liste CVE filtrée (mêmes filtres que ``vulnerability_list``)."""
    qs, _ = _filter_cves(request)
    return _stream_cves_csv(qs.order_by("cve_id"), "cve_filtrees.csv")


def export_alerts(request) -> StreamingHttpResponse:
    """Export CSV des alertes filtrées (mêmes filtres que ``alerts``)."""
    qs, _ = _filtered_alert_cves(request)
    return _stream_cves_csv(qs, "alertes_filtrees.csv")
