"""Génère notebook.ipynb (étapes 5-7 : EDA, visualisations, ML, alertes).

Script utilitaire one-shot : construit le notebook cellule par cellule avec
nbformat, puis on l'exécute via nbconvert pour produire les sorties + le HTML.
"""

import nbformat as nbf

nb = nbf.v4.new_notebook()
cells = []


def md(text):
    cells.append(nbf.v4.new_markdown_cell(text))


def code(src):
    cells.append(nbf.v4.new_code_cell(src))


# ---------------------------------------------------------------- Intro
md(
    """# Analyse des vulnérabilités ANSSI — Étapes 5 à 7

Ce notebook prolonge le pipeline (étapes 1-4 : extraction RSS/dump local →
identification des CVE → enrichissement MITRE/EPSS → CSV consolidé). Il couvre :

- **Étape 5** — exploration et visualisation du `data/consolidated.csv`.
- **Étape 6** — modèles de Machine Learning (1 supervisé + 1 non supervisé) avec validation.
- **Étape 7** — génération d'alertes email personnalisées pour les vulnérabilités critiques.

Périmètre des données : bulletins CERT-FR (avis + alertes) 2024–2026."""
)

# ---------------------------------------------------------------- Chargement
code(
    """import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid")
plt.rcParams["figure.figsize"] = (10, 5)
pd.set_option("display.max_columns", None)

df = pd.read_csv("data/consolidated.csv")

# Typage : scores numériques, date en datetime.
df["score_cvss"] = pd.to_numeric(df["score_cvss"], errors="coerce")
df["score_epss"] = pd.to_numeric(df["score_epss"], errors="coerce")
df["date_publication"] = pd.to_datetime(df["date_publication"], errors="coerce", utc=True)
df["annee"] = df["date_publication"].dt.year

print("Lignes (couples bulletin × CVE) :", len(df))
print("Bulletins uniques :", df["id_anssi"].nunique())
print("CVE uniques :", df["cve_id"].nunique())
df.head()"""
)

# ---------------------------------------------------------------- Étape 5 EDA
md(
    """## Étape 5 — Exploration des données

Une ligne = un couple (bulletin × CVE) : un bulletin multi-CVE est donc répété.
Pour les analyses **au niveau vulnérabilité** (distribution des scores, types CWE…),
on dédoublonne sur `cve_id` afin de ne pas surpondérer les CVE citées par plusieurs
bulletins. Les analyses **au niveau bulletin/éditeur** gardent le détail complet."""
)

code(
    """df.info()
df.describe(include="all").T"""
)

code(
    """# Valeurs manquantes / indisponibles
na_num = df[["score_cvss", "score_epss"]].isna().mean().mul(100).round(1)
indispo = (df[["type_cwe", "editeur", "produit"]] == "Non disponible").mean().mul(100).round(1)
print("% valeurs manquantes (numériques) :")
print(na_num.to_string())
print("\\n% 'Non disponible' (texte) :")
print(indispo.to_string())"""
)

code(
    """# Vue au niveau vulnérabilité (1 ligne par CVE)
cve = df.drop_duplicates("cve_id").copy()
print("CVE uniques :", len(cve))
print("\\nRépartition des gravités :")
print(cve["base_severity"].value_counts())
print("\\nTop 10 éditeurs (par nb de couples bulletin×CVE) :")
print(df[df["editeur"] != "Non disponible"]["editeur"].value_counts().head(10))"""
)

# ---------------------------------------------------------------- Visualisations
md("## Étape 5 — Visualisations")

code(
    """# 1) Histogramme des scores CVSS
plt.figure()
sns.histplot(cve["score_cvss"].dropna(), bins=20, kde=True, color="steelblue")
plt.title("Distribution des scores CVSS (niveau CVE)")
plt.xlabel("Score CVSS (0-10)"); plt.ylabel("Nombre de CVE")
plt.show()"""
)

code(
    """# 2) Répartition des gravités (base_severity)
order = ["Faible", "Moyenne", "Élevée", "Critique", "Non disponible"]
plt.figure()
sns.countplot(data=cve, x="base_severity", order=[o for o in order if o in cve["base_severity"].unique()],
              palette="rocket")
plt.title("Répartition des CVE par gravité")
plt.xlabel(""); plt.ylabel("Nombre de CVE")
plt.show()"""
)

code(
    """# 3) Camembert des types CWE les plus fréquents (top 10)
cwe_counts = cve[cve["type_cwe"] != "Non disponible"]["type_cwe"].value_counts().head(10)
plt.figure(figsize=(8, 8))
plt.pie(cwe_counts, labels=cwe_counts.index, autopct="%1.1f%%", startangle=90,
        colors=sns.color_palette("tab20", len(cwe_counts)))
plt.title("Top 10 des types de vulnérabilités (CWE)")
plt.show()"""
)

code(
    """# 4) Courbe des scores EPSS triés (probabilité d'exploitation)
epss_sorted = cve["score_epss"].dropna().sort_values(ascending=False).reset_index(drop=True)
plt.figure()
plt.plot(epss_sorted.values, color="darkred")
plt.title("Scores EPSS triés (probabilité d'exploitation)")
plt.xlabel("CVE (rang)"); plt.ylabel("Score EPSS (0-1)")
plt.yscale("log")
plt.show()"""
)

code(
    """# 5) Top 15 éditeurs les plus affectés
top_ed = df[df["editeur"] != "Non disponible"]["editeur"].value_counts().head(15)
plt.figure(figsize=(10, 6))
sns.barplot(x=top_ed.values, y=top_ed.index, palette="viridis")
plt.title("Top 15 des éditeurs les plus affectés")
plt.xlabel("Nombre de couples bulletin × CVE"); plt.ylabel("")
plt.show()"""
)

code(
    """# 6) Top 15 produits les plus affectés
top_prod = df[df["produit"] != "Non disponible"]["produit"].value_counts().head(15)
plt.figure(figsize=(10, 6))
sns.barplot(x=top_prod.values, y=top_prod.index, palette="mako")
plt.title("Top 15 des produits les plus affectés")
plt.xlabel("Nombre de couples bulletin × CVE"); plt.ylabel("")
plt.show()"""
)

code(
    """# 7) Heatmap de corrélation CVSS / EPSS
corr = cve[["score_cvss", "score_epss"]].dropna().corr()
plt.figure(figsize=(5, 4))
sns.heatmap(corr, annot=True, cmap="coolwarm", vmin=-1, vmax=1, fmt=".2f")
plt.title("Corrélation CVSS ↔ EPSS")
plt.show()"""
)

code(
    """# 8) Nuage de points CVSS vs EPSS
sub = cve[["score_cvss", "score_epss"]].dropna()
plt.figure()
plt.scatter(sub["score_cvss"], sub["score_epss"], alpha=0.2, s=10, color="purple")
plt.title("Score EPSS en fonction du score CVSS")
plt.xlabel("Score CVSS"); plt.ylabel("Score EPSS")
plt.show()"""
)

code(
    """# 9) Courbe cumulative des vulnérabilités dans le temps
ts = df.drop_duplicates("cve_id").dropna(subset=["date_publication"]).sort_values("date_publication")
ts_cum = ts.set_index("date_publication").assign(n=1)["n"].cumsum()
plt.figure()
ts_cum.plot(color="teal")
plt.title("Nombre cumulé de CVE découvertes dans le temps")
plt.xlabel("Date"); plt.ylabel("CVE cumulées")
plt.show()"""
)

code(
    """# 10) Boxplot des scores CVSS par éditeur (top 8 éditeurs)
top8 = df[df["editeur"] != "Non disponible"]["editeur"].value_counts().head(8).index
box = df[df["editeur"].isin(top8)].dropna(subset=["score_cvss"])
plt.figure(figsize=(11, 6))
sns.boxplot(data=box, x="score_cvss", y="editeur", order=top8, palette="Set2")
plt.title("Dispersion des scores CVSS par éditeur (top 8)")
plt.xlabel("Score CVSS"); plt.ylabel("")
plt.show()"""
)

code(
    """# 11) Vulnérabilités par éditeur et type de bulletin (avis vs alerte)
ct = (df[df["editeur"].isin(top8)]
      .groupby(["editeur", "type_bulletin"]).size().unstack(fill_value=0)
      .reindex(top8))
ct.plot(kind="barh", stacked=True, figsize=(11, 6), colormap="Accent")
plt.title("Avis vs Alertes par éditeur (top 8)")
plt.xlabel("Nombre de couples bulletin × CVE"); plt.ylabel("")
plt.legend(title="Type")
plt.show()"""
)

# ---------------------------------------------------------------- Étape 6 ML
md(
    """## Étape 6 — Machine Learning

Deux modèles complémentaires sur les CVE enrichies :

1. **Supervisé — classification de la gravité (`base_severity`).**
   Cible : Faible / Moyenne / Élevée / Critique. Variables explicatives : `score_epss`,
   `type_cwe`, `type_bulletin`, `editeur` (top-N).
   *Important :* on **n'utilise pas** `score_cvss` comme variable, car `base_severity`
   en est dérivée déterministe (fuite de cible). Question posée : peut-on prédire la
   gravité à partir d'autres signaux (probabilité d'exploitation, type de faille, éditeur) ?

2. **Non supervisé — clustering KMeans** sur (`score_cvss`, `score_epss`) pour faire
   émerger des profils de risque (ex. critique & fortement exploitable)."""
)

code(
    """from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import (classification_report, confusion_matrix,
                             ConfusionMatrixDisplay, silhouette_score)

# Jeu d'apprentissage : 1 ligne par CVE, gravité connue.
ml = cve[cve["base_severity"] != "Non disponible"].copy()
ml = ml.dropna(subset=["score_epss"])

# Réduire la cardinalité : éditeur top-20, sinon 'Autre' ; CWE top-20.
def topn(s, n=20):
    top = s.value_counts().head(n).index
    return s.where(s.isin(top), "Autre")

ml["editeur_grp"] = topn(ml["editeur"])
ml["cwe_grp"] = topn(ml["type_cwe"])

features = pd.get_dummies(
    ml[["score_epss", "type_bulletin", "editeur_grp", "cwe_grp"]],
    columns=["type_bulletin", "editeur_grp", "cwe_grp"],
)
target = ml["base_severity"]
print("Échantillon ML :", features.shape, "| classes :", dict(target.value_counts()))"""
)

code(
    """# --- Supervisé : Random Forest ---
X_train, X_test, y_train, y_test = train_test_split(
    features, target, test_size=0.25, random_state=42, stratify=target)

rf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced", n_jobs=-1)
rf.fit(X_train, y_train)
y_pred = rf.predict(X_test)

print("Rapport de classification (jeu de test) :\\n")
print(classification_report(y_test, y_pred))"""
)

code(
    """# Matrice de confusion
labels = ["Faible", "Moyenne", "Élevée", "Critique"]
labels = [l for l in labels if l in target.unique()]
cm = confusion_matrix(y_test, y_pred, labels=labels)
ConfusionMatrixDisplay(cm, display_labels=labels).plot(cmap="Blues", xticks_rotation=45)
plt.title("Matrice de confusion — gravité prédite")
plt.show()"""
)

code(
    """# Validation croisée + importance des variables
cv = cross_val_score(rf, features, target, cv=5, scoring="f1_macro", n_jobs=-1)
print(f"F1-macro cross-val (5 folds) : {cv.mean():.3f} ± {cv.std():.3f}")

imp = pd.Series(rf.feature_importances_, index=features.columns).sort_values(ascending=False).head(12)
plt.figure(figsize=(9, 5))
sns.barplot(x=imp.values, y=imp.index, palette="flare")
plt.title("Top 12 des variables les plus importantes (Random Forest)")
plt.xlabel("Importance"); plt.ylabel("")
plt.show()"""
)

code(
    """# --- Non supervisé : KMeans sur (CVSS, EPSS) ---
clu = cve.dropna(subset=["score_cvss", "score_epss"])[["score_cvss", "score_epss"]].copy()
Xc = StandardScaler().fit_transform(clu)

# Choix de k : méthode du coude + silhouette
inertias, sils, ks = [], [], range(2, 8)
for k in ks:
    km = KMeans(n_clusters=k, random_state=42, n_init=10).fit(Xc)
    inertias.append(km.inertia_)
    sils.append(silhouette_score(Xc, km.labels_, sample_size=10000, random_state=42))

fig, ax = plt.subplots(1, 2, figsize=(13, 4))
ax[0].plot(list(ks), inertias, "o-"); ax[0].set_title("Méthode du coude"); ax[0].set_xlabel("k"); ax[0].set_ylabel("Inertie")
ax[1].plot(list(ks), sils, "o-", color="green"); ax[1].set_title("Score de silhouette"); ax[1].set_xlabel("k"); ax[1].set_ylabel("Silhouette")
plt.show()
print("Silhouette par k :", {k: round(s, 3) for k, s in zip(ks, sils)})"""
)

code(
    """# KMeans final (k=4) + interprétation des clusters
k = 4
km = KMeans(n_clusters=k, random_state=42, n_init=10).fit(Xc)
clu["cluster"] = km.labels_

plt.figure()
sns.scatterplot(data=clu, x="score_cvss", y="score_epss", hue="cluster",
                palette="tab10", alpha=0.4, s=15)
plt.title(f"Clusters KMeans (k={k}) — CVSS vs EPSS")
plt.xlabel("Score CVSS"); plt.ylabel("Score EPSS")
plt.show()

print("Profil moyen par cluster :")
print(clu.groupby("cluster")[["score_cvss", "score_epss"]].agg(["mean", "count"]).round(3))"""
)

md(
    """### Conclusions ML

- **Supervisé** : la gravité reste partiellement prévisible à partir de l'EPSS, du type
  CWE et de l'éditeur (cf. F1-macro). Les confusions se concentrent entre classes
  adjacentes (Élevée ↔ Critique), ce qui est attendu puisque la frontière CVSS y est
  fine et que l'on s'interdit d'utiliser le CVSS lui-même.
- **Non supervisé** : KMeans fait émerger des **profils de risque** — typiquement un
  cluster « score élevé + forte probabilité d'exploitation » à prioriser pour les alertes,
  et des clusters « gravité élevée mais faible exploitabilité » moins urgents."""
)

# ---------------------------------------------------------------- Étape 7 email
md(
    """## Étape 7 — Génération d'alertes email

On cible les vulnérabilités **critiques et activement exploitables** (CVSS élevé
**et/ou** EPSS élevé) sur des produits affectés, et on génère un **sujet + corps**
de mail personnalisé. L'envoi SMTP est volontairement laissé optionnel (cf. sujet)."""
)

code(
    """CVSS_SEUIL = 9.0   # gravité critique
EPSS_SEUIL = 0.5   # forte probabilité d'exploitation

alertes = df[(df["score_cvss"] >= CVSS_SEUIL) | (df["score_epss"] >= EPSS_SEUIL)].copy()
alertes = alertes.sort_values(["score_epss", "score_cvss"], ascending=False)
print(f"{len(alertes)} couples bulletin×CVE déclenchent une alerte "
      f"({alertes['cve_id'].nunique()} CVE, {alertes['id_anssi'].nunique()} bulletins).")
alertes[["id_anssi", "cve_id", "score_cvss", "base_severity", "score_epss", "editeur", "produit"]].head(10)"""
)

code(
    '''def build_alert_email(row) -> tuple[str, str]:
    """Construit (sujet, corps) d'un mail d'alerte pour une vulnérabilité."""
    cvss = "N/A" if pd.isna(row["score_cvss"]) else f"{row['score_cvss']:.1f}"
    epss = "N/A" if pd.isna(row["score_epss"]) else f"{row['score_epss']:.1%}"
    sujet = f"[Alerte sécurité] {row['cve_id']} — {row['base_severity']} sur {row['produit']}"
    corps = f"""Bonjour,

Une vulnérabilité critique a été identifiée concernant un produit que vous suivez.

  • CVE          : {row['cve_id']}
  • Produit      : {row['produit']} ({row['editeur']})
  • Versions     : {row['versions_affectees']}
  • Gravité CVSS : {cvss} / 10 ({row['base_severity']})
  • Exploitation : probabilité EPSS {epss}
  • Type (CWE)   : {row['type_cwe']}
  • Bulletin     : {row['id_anssi']} — {row['lien_bulletin']}

Description : {str(row['description'])[:400]}

Action recommandée : appliquer sans délai les correctifs de l'éditeur et vérifier
l'exposition de vos systèmes.

— Veille automatisée CVE / CERT-FR"""
    return sujet, corps


# Exemples sur les 3 alertes les plus prioritaires
for _, row in alertes.head(3).iterrows():
    sujet, corps = build_alert_email(row)
    print("=" * 80)
    print("SUJET :", sujet)
    print("-" * 80)
    print(corps)
    print()'''
)

code(
    '''# Envoi SMTP (OPTIONNEL — désactivé). À activer avec un mot de passe d'application.
def send_email(to_email, subject, body, from_email="votre_email@gmail.com", password=None):
    """Envoie un mail via SMTP Gmail. Laissé optionnel (cf. sujet)."""
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(body)
    msg["From"], msg["To"], msg["Subject"] = from_email, to_email, subject
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())

print("Fonction d'envoi définie (non appelée : nécessite des identifiants).")'''
)

md(
    """## Synthèse

- **Étape 5** : exploration + 11 visualisations (gravité, CWE, EPSS, éditeurs/produits,
  corrélation, temporalité, dispersion).
- **Étape 6** : Random Forest (classification de gravité, validé par cross-val + matrice
  de confusion) et KMeans (profils de risque, validé par coude + silhouette).
- **Étape 7** : génération automatique de sujets/corps d'alertes pour les CVE critiques."""
)

nb["cells"] = cells
nb["metadata"]["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
with open("notebook.ipynb", "w", encoding="utf-8") as f:
    nbf.write(nb, f)
print("notebook.ipynb généré :", len(cells), "cellules")
