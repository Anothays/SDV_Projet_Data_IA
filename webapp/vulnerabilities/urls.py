"""Routes de l'app vulnerabilities."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("cve/", views.vulnerability_list, name="cve_list"),
    path("cve/export.csv", views.export_cves, name="cve_export"),
    path("cve/<str:cve_id>/", views.vulnerability_detail, name="cve_detail"),
    path("bulletins/", views.bulletin_list, name="bulletin_list"),
    path("bulletins/<str:id_anssi>/", views.bulletin_detail, name="bulletin_detail"),
    path("alertes/", views.alerts, name="alerts"),
    path("alertes/export.csv", views.export_alerts, name="alerts_export"),
]
