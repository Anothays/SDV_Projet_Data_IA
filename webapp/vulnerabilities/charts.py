"""Graphiques Plotly du tableau de bord (étape 5 du notebook portée en web).

On lit les données via l'ORM. La table ``Cve`` est déjà au **niveau vulnérabilité**
(1 ligne par ``cve_id``), ce qui évite le biais des CVE citées par plusieurs
bulletins (cf. note méthodologique du notebook). Chaque figure est renvoyée sous
forme de fragment HTML ; ``plotly.js`` est chargé une seule fois via CDN dans
``base.html`` → ``include_plotlyjs=False``.
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from django.db.models import Min

from .models import UNAVAILABLE, Cve

# Ordre croissant de gravité pour l'axe du graphe (sans la sentinelle).
SEVERITY_ORDER = ["Faible", "Moyenne", "Élevée", "Critique"]
SEVERITY_COLORS = {
    "Faible": "#4caf50",
    "Moyenne": "#ffc107",
    "Élevée": "#ff9800",
    "Critique": "#f44336",
}
PLOTLY_CONFIG = {"displayModeBar": False, "responsive": True}


def _fig_html(fig) -> str:
    """Met en forme une figure et renvoie son fragment HTML (sans plotly.js)."""
    fig.update_layout(
        margin=dict(l=50, r=20, t=55, b=45),
        height=380,
        title_x=0.5,
        template="plotly_white",
    )
    return fig.to_html(full_html=False, include_plotlyjs=False, config=PLOTLY_CONFIG)


def _cve_dataframe() -> pd.DataFrame:
    """DataFrame niveau CVE pour les distributions et classements."""
    rows = Cve.objects.values(
        "cve_id", "score_cvss", "base_severity", "type_cwe", "score_epss", "editeur"
    )
    return pd.DataFrame.from_records(rows)


def build_dashboard_charts() -> dict[str, str]:
    """Construit tous les graphiques du dashboard → dict {clé: fragment HTML}."""
    df = _cve_dataframe()
    if df.empty:
        return {}

    return {
        "cvss_hist": _cvss_histogram(df),
        "severity_bar": _severity_bar(df),
        "cwe_pie": _cwe_pie(df),
        "epss_curve": _epss_curve(df),
        "top_editeurs": _top_editeurs(df),
        "cvss_epss_scatter": _cvss_epss_scatter(df),
        "timeline": _cumulative_timeline(),
    }


def _cvss_histogram(df: pd.DataFrame) -> str:
    cvss = df["score_cvss"].dropna()
    fig = px.histogram(
        x=cvss, nbins=20, color_discrete_sequence=["steelblue"],
        title="Distribution des scores CVSS (niveau CVE)",
    )
    fig.update_layout(xaxis_title="Score CVSS (0-10)", yaxis_title="Nombre de CVE", bargap=0.05)
    return _fig_html(fig)


def _severity_bar(df: pd.DataFrame) -> str:
    sev = (
        df.loc[df["base_severity"] != UNAVAILABLE, "base_severity"]
        .value_counts()
        .reindex(SEVERITY_ORDER)
        .dropna()
    )
    fig = px.bar(
        x=sev.index, y=sev.values, color=sev.index,
        color_discrete_map=SEVERITY_COLORS,
        title="Répartition des CVE par gravité",
    )
    fig.update_layout(xaxis_title="", yaxis_title="Nombre de CVE", showlegend=False)
    return _fig_html(fig)


def _cwe_pie(df: pd.DataFrame) -> str:
    cwe = df.loc[df["type_cwe"] != UNAVAILABLE, "type_cwe"].value_counts().head(10)
    fig = px.pie(
        values=cwe.values, names=cwe.index, hole=0.3,
        title="Top 10 des types de vulnérabilités (CWE)",
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    return _fig_html(fig)


def _epss_curve(df: pd.DataFrame) -> str:
    epss = df["score_epss"].dropna().sort_values(ascending=False).reset_index(drop=True)
    fig = go.Figure(go.Scatter(y=epss.values, mode="lines", line=dict(color="darkred")))
    fig.update_layout(
        title="Scores EPSS triés (probabilité d'exploitation)",
        xaxis_title="CVE (rang)", yaxis_title="Score EPSS (échelle log)",
    )
    fig.update_yaxes(type="log")
    return _fig_html(fig)


def _top_editeurs(df: pd.DataFrame) -> str:
    top = (
        df.loc[df["editeur"] != UNAVAILABLE, "editeur"]
        .value_counts()
        .head(15)
        .sort_values()
    )
    fig = px.bar(
        x=top.values, y=top.index, orientation="h",
        color=top.values, color_continuous_scale="Viridis",
        title="Top 15 des éditeurs les plus affectés",
    )
    fig.update_layout(xaxis_title="Nombre de CVE", yaxis_title="", coloraxis_showscale=False)
    return _fig_html(fig)


def _cvss_epss_scatter(df: pd.DataFrame) -> str:
    sub = df[["score_cvss", "score_epss"]].dropna()
    fig = px.scatter(
        sub, x="score_cvss", y="score_epss", opacity=0.3,
        render_mode="webgl", color_discrete_sequence=["purple"],
        title="EPSS en fonction du CVSS (gravité ↔ exploitabilité)",
    )
    fig.update_layout(xaxis_title="Score CVSS", yaxis_title="Score EPSS")
    return _fig_html(fig)


def _cumulative_timeline() -> str:
    """Courbe cumulative des CVE par date de 1ʳᵉ publication (plus ancien bulletin)."""
    rows = (
        Cve.objects.annotate(date=Min("bulletins__date_publication"))
        .values("cve_id", "date")
    )
    ts = pd.DataFrame.from_records(rows).dropna(subset=["date"])
    if ts.empty:
        return ""
    ts["date"] = pd.to_datetime(ts["date"], utc=True)
    ts = ts.sort_values("date")
    ts["cumul"] = range(1, len(ts) + 1)
    fig = px.line(ts, x="date", y="cumul", color_discrete_sequence=["teal"],
                  title="Nombre cumulé de CVE découvertes dans le temps")
    fig.update_layout(xaxis_title="Date", yaxis_title="CVE cumulées")
    return _fig_html(fig)
