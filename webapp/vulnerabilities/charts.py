"""Graphiques Plotly du tableau de bord (étape 5 du notebook portée en web).

On lit les données via l'ORM. La table ``Cve`` est déjà au **niveau vulnérabilité**
(1 ligne par ``cve_id``), ce qui évite le biais des CVE citées par plusieurs
bulletins (cf. note méthodologique du notebook).

Chaque graphique est renvoyé sous forme de **carte pédagogique** : un fragment
HTML Plotly, une explication en langage courant (``lede``) et une phrase
« à retenir » calculée à partir des données (``takeaway``). ``plotly.js`` est
chargé une seule fois via CDN dans ``base.html`` → ``include_plotlyjs=False``.
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


def _card(html: str, lede: str, takeaway: str = "", full_width: bool = False) -> dict:
    """Assemble une carte pédagogique pour le template du dashboard."""
    return {"html": html, "lede": lede, "takeaway": takeaway, "full_width": full_width}


def _pct(part: float, whole: float) -> str:
    """Formate un pourcentage à la française (ex. ``23 %``)."""
    if not whole:
        return "0 %"
    return f"{round(100 * part / whole)} %".replace(".", ",")


def _cve_dataframe() -> pd.DataFrame:
    """DataFrame niveau CVE pour les distributions et classements."""
    rows = Cve.objects.values(
        "cve_id", "score_cvss", "base_severity", "type_cwe", "score_epss", "editeur"
    )
    return pd.DataFrame.from_records(rows)


def build_dashboard_charts() -> list[dict]:
    """Construit toutes les cartes du dashboard → liste ordonnée de dicts."""
    df = _cve_dataframe()
    if df.empty:
        return []

    cards = [
        _cvss_histogram(df),
        _severity_bar(df),
        _cwe_pie(df),
        _epss_curve(df),
        _top_editeurs(df),
        _cvss_epss_scatter(df),
    ]
    timeline = _cumulative_timeline()
    if timeline is not None:
        cards.append(timeline)
    return cards


def _cvss_histogram(df: pd.DataFrame) -> dict:
    cvss = df["score_cvss"].dropna()
    fig = px.histogram(
        x=cvss, nbins=20, color_discrete_sequence=["steelblue"],
        title="Distribution des scores CVSS (niveau CVE)",
    )
    fig.update_layout(xaxis_title="Score CVSS (0-10)", yaxis_title="Nombre de CVE", bargap=0.05)
    n_high = int((cvss >= 7).sum())
    return _card(
        _fig_html(fig),
        "Chaque faille reçoit une note de gravité de 0 à 10 (CVSS). Ce graphique "
        "montre combien de failles tombent dans chaque tranche de note.",
        f"{_pct(n_high, len(cvss))} des failles ont un score élevé à critique "
        f"(7 ou plus sur 10).",
    )


def _severity_bar(df: pd.DataFrame) -> dict:
    valid = df.loc[df["base_severity"] != UNAVAILABLE, "base_severity"]
    sev = valid.value_counts().reindex(SEVERITY_ORDER).dropna()
    fig = px.bar(
        x=sev.index, y=sev.values, color=sev.index,
        color_discrete_map=SEVERITY_COLORS,
        title="Répartition des CVE par gravité",
    )
    fig.update_layout(xaxis_title="", yaxis_title="Nombre de CVE", showlegend=False)
    n_crit = int(sev.get("Critique", 0))
    return _card(
        _fig_html(fig),
        "Répartition des failles selon leur niveau de danger, du moins grave "
        "(Faible) au plus grave (Critique).",
        f"{n_crit} failles sont classées « Critiques », soit "
        f"{_pct(n_crit, len(valid))} des failles évaluées.",
    )


def _cwe_pie(df: pd.DataFrame) -> dict:
    valid = df.loc[df["type_cwe"] != UNAVAILABLE, "type_cwe"]
    cwe = valid.value_counts().head(10)
    fig = px.pie(
        values=cwe.values, names=cwe.index, hole=0.3,
        title="Top 10 des types de vulnérabilités (CWE)",
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    takeaway = ""
    if not cwe.empty:
        takeaway = (
            f"Le type de faiblesse le plus fréquent est « {cwe.index[0]} » "
            f"({_pct(int(cwe.iloc[0]), len(valid))} des failles)."
        )
    return _card(
        _fig_html(fig),
        "Le CWE décrit la nature technique de la faiblesse à l'origine de la "
        "faille (injection, débordement mémoire, mauvaise authentification…).",
        takeaway,
    )


def _epss_curve(df: pd.DataFrame) -> dict:
    epss = df["score_epss"].dropna().sort_values(ascending=False).reset_index(drop=True)
    fig = go.Figure(go.Scatter(y=epss.values, mode="lines", line=dict(color="darkred")))
    fig.update_layout(
        title="Scores EPSS triés (probabilité d'exploitation)",
        xaxis_title="Failles classées de la plus à la moins risquée",
        yaxis_title="Probabilité d'exploitation (échelle log)",
    )
    fig.update_yaxes(type="log")
    n_risky = int((epss >= 0.5).sum())
    return _card(
        _fig_html(fig),
        "L'EPSS estime la probabilité qu'une faille soit réellement exploitée "
        "par des attaquants. Les failles sont ici classées de la plus à la "
        "moins susceptible d'être exploitée (l'axe vertical est compressé pour "
        "rester lisible).",
        f"{n_risky} failles ont plus d'une chance sur deux d'être exploitées "
        "(EPSS ≥ 0,5).",
    )


def _top_editeurs(df: pd.DataFrame) -> dict:
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
    takeaway = ""
    if not top.empty:
        leader = top.index[-1]  # trié croissant → dernier = plus affecté
        takeaway = f"« {leader} » arrive en tête avec {int(top.iloc[-1])} failles recensées."
    return _card(
        _fig_html(fig),
        "Les éditeurs (entreprises qui développent les logiciels) dont les "
        "produits concentrent le plus de failles recensées. Un éditeur très "
        "présent est souvent un éditeur très utilisé, pas forcément moins sûr.",
        takeaway,
    )


def _cvss_epss_scatter(df: pd.DataFrame) -> dict:
    sub = df[["score_cvss", "score_epss"]].dropna()
    fig = px.scatter(
        sub, x="score_cvss", y="score_epss", opacity=0.3,
        render_mode="webgl", color_discrete_sequence=["purple"],
        title="Gravité (CVSS) face à la probabilité d'exploitation (EPSS)",
    )
    fig.update_layout(xaxis_title="Gravité — score CVSS", yaxis_title="Probabilité d'exploitation — EPSS")
    n_prio = int(((sub["score_cvss"] >= 7) & (sub["score_epss"] >= 0.5)).sum())
    return _card(
        _fig_html(fig),
        "Chaque point est une faille. Plus elle est à droite, plus elle est "
        "grave ; plus elle est en haut, plus elle risque d'être exploitée. "
        "Les points en haut à droite sont les plus préoccupants : graves ET "
        "probablement exploités.",
        f"{n_prio} failles cumulent forte gravité (CVSS ≥ 7) et forte "
        "probabilité d'exploitation (EPSS ≥ 0,5) : à traiter en priorité.",
    )


def _cumulative_timeline() -> dict | None:
    """Courbe cumulative des CVE par date de 1ʳᵉ publication (plus ancien bulletin)."""
    rows = (
        Cve.objects.annotate(date=Min("bulletins__date_publication"))
        .values("cve_id", "date")
    )
    ts = pd.DataFrame.from_records(rows).dropna(subset=["date"])
    if ts.empty:
        return None
    ts["date"] = pd.to_datetime(ts["date"], utc=True)
    ts = ts.sort_values("date")
    ts["cumul"] = range(1, len(ts) + 1)
    fig = px.line(ts, x="date", y="cumul", color_discrete_sequence=["teal"],
                  title="Nombre cumulé de CVE découvertes dans le temps")
    fig.update_layout(xaxis_title="Date", yaxis_title="CVE cumulées")
    debut, fin = ts["date"].iloc[0], ts["date"].iloc[-1]
    return _card(
        _fig_html(fig),
        "Nombre total de failles recensées qui s'accumule au fil du temps. "
        "Une pente qui s'accentue signale une activité de publication en hausse.",
        f"{len(ts)} failles recensées entre {debut:%B %Y} et {fin:%B %Y}.",
        full_width=True,
    )
