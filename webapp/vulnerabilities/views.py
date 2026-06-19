"""Vues de la web app : tableau de bord, listes filtrables, détails, alertes."""

from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, render

from .alerts import alert_cves, build_alert_email
from .charts import build_dashboard_charts
from .models import SEVERITY_ORDER, Bulletin, Cve

PAGE_SIZE = 25


def _querystring_without_page(request) -> str:
    """Querystring courant sans le paramètre ``page`` (pour les liens de pagination)."""
    params = request.GET.copy()
    params.pop("page", None)
    return params.urlencode()


def _published_years() -> list[int]:
    """Années de publication présentes en base (pour le filtre déroulant)."""
    dates = Bulletin.objects.exclude(date_publication=None).dates("date_publication", "year")
    return sorted({d.year for d in dates}, reverse=True)


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


def vulnerability_list(request):
    """Liste paginée et filtrable des CVE."""
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
        qs = qs.filter(editeur__icontains=filters["editeur"])
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

    qs = qs.order_by("-score_cvss", "cve_id")
    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page"))
    context = {
        "page_obj": page,
        "filters": filters,
        "severities": SEVERITY_ORDER,
        "years": _published_years(),
        "base_query": _querystring_without_page(request),
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

    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page"))
    context = {
        "page_obj": page,
        "filters": filters,
        "types": list(Bulletin.objects.values_list("type_bulletin", flat=True).distinct()),
        "years": _published_years(),
        "base_query": _querystring_without_page(request),
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


def alerts(request):
    """Alertes critiques (CVSS ≥ 9 ou EPSS ≥ 0.5) + aperçus d'email."""
    qs = alert_cves()
    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page"))

    # Aperçus email pour les 3 alertes les plus prioritaires (cf. notebook étape 7).
    previews = []
    for cve in qs[:3]:
        sujet, corps = build_alert_email(cve)
        previews.append({"sujet": sujet, "corps": corps})

    context = {
        "page_obj": page,
        "total": page.paginator.count,
        "previews": previews,
        "base_query": _querystring_without_page(request),
    }
    return render(request, "vulnerabilities/alerts.html", context)
