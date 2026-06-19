# Analyse des avis et alertes ANSSI avec enrichissement des CVE

Pipeline Python qui extrait les bulletins de sécurité du CERT-FR (ANSSI),
identifie les CVE référencées, les enrichit via les API **MITRE** (CVSS, CWE) et
**EPSS/FIRST** (probabilité d'exploitation), puis consolide le tout dans un
fichier CSV exploitable.

> Périmètre : **étapes 1 à 7** du sujet. Le pipeline (`src/anssi_cve/`) couvre
> l'extraction → l'enrichissement → la consolidation → le CSV. Le notebook
> (`notebook.ipynb`, exporté en `notebook.html`) couvre l'exploration et les
> visualisations (étape 5), le Machine Learning (étape 6) et la génération
> d'alertes email (étape 7) à partir du CSV produit. En **bonus** (« Pour aller
> loin »), une **web app Django** (`webapp/`) rend le `consolidated.csv`
> consultable : tableau de bord interactif, listes filtrables et page d'alertes
> « sur mesure » (cf. section dédiée plus bas).

## Source des données

Le pipeline lit le **dump local fourni** (section 8 du sujet : `data/Avis/`,
`data/alertes/`, `data/mitre/`, `data/first/`) : un fichier JSON par bulletin /
CVE, identique à ce que renverraient les API. Avantage : zéro latence, zéro
charge sur les serveurs externes. Les bulletins viennent **exclusivement** du
dump ; seul l'**enrichissement** MITRE/EPSS conserve un repli réseau (avec
rate-limiting) pour une CVE qui n'aurait pas sa réponse pré-téléchargée.

## Prérequis

- **Python ≥ 3.13**.
- **[uv](https://docs.astral.sh/uv/)** (gestionnaire de paquets et d'environnement).
- Le **dump local** présent sous `data/` (`Avis/`, `alertes/`, `mitre/`, `first/`).
- Quelques **Go d'espace disque** : le `consolidated.csv` peut être volumineux
  (cf. *Points de vigilance*).
- Un **navigateur** pour la web app bonus. OS indifférent (macOS / Linux / Windows).

## Installation

```bash
uv sync
```

Installe les dépendances et le package en mode éditable (src-layout).

## Structure du projet

```
src/anssi_cve/
  config.py          # API MITRE/EPSS, délais, chemins, OFFLINE_ONLY, DEFAULT_YEARS
  local_source.py    # étapes 1-2 : lecture des bulletins du dump (data/Avis + data/alertes)
  cve_extraction.py  # étape 2 : CVE référencées dans le JSON d'un bulletin
  enrichment.py      # étape 3 : enrichissement MITRE (CVSS/CWE) + EPSS, dump puis API en repli
  consolidation.py   # étape 4 : DataFrame pandas (1 ligne par couple bulletin × CVE)
  http_client.py     # repli réseau responsable : rate-limit + retry + cache disque
  pipeline.py        # orchestration end-to-end → data/consolidated.csv
data/
  Avis/, alertes/    # dump local des bulletins ANSSI (fourni)
  mitre/, first/     # dump local des réponses API CVE/EPSS (fourni)
  cache/             # cache JSON du repli réseau (régénérable, non versionné)
  consolidated.csv   # livrable 2 : données consolidées (généré)
main.py              # point d'entrée du pipeline
notebook.ipynb       # livrable 3 : étapes 5-7 (EDA, visualisations, ML, alertes)
notebook.html        # export HTML du notebook
webapp/              # bonus Django (consultation du CSV) — cf. section dédiée
```

## Lancement

### 1. Pipeline → CSV consolidé (étapes 1-4)

```bash
uv run python main.py                 # ou : uv run python -m anssi_cve.pipeline
```

Lit le dump local et écrit `data/consolidated.csv`. Deux réglages dans
`src/anssi_cve/config.py` :

- `OFFLINE_ONLY = True` (défaut) : **aucun appel réseau** (une CVE absente du
  dump est marquée `Non disponible`). Passer à `False` pour activer le repli API.
- `DEFAULT_YEARS = None` (défaut) : **tout le dump** est traité (plusieurs
  milliers de bulletins). Passer un tuple d'années (ex. `(2024, 2025, 2026)`)
  pour restreindre le périmètre et **alléger** le CSV.

### 2. Notebook → analyses + export HTML (étapes 5-7)

```bash
uv run jupyter nbconvert --to notebook --execute --inplace notebook.ipynb
uv run jupyter nbconvert --to html notebook.ipynb        # → notebook.html
```

Le notebook charge `data/consolidated.csv`, puis enchaîne exploration,
visualisations, Machine Learning (modèles supervisés + non supervisés avec
validation) et génération d'alertes email. On peut aussi l'ouvrir directement
dans Jupyter et faire **Restart & Run All**.

### 3. Web app Django (bonus)

Voir la section [Web app Django](#web-app-django-étape-7--pour-aller-loin-bonus).

## Accès responsable aux ressources externes (section 8)

Le dump local fait foi. Quand le repli réseau **enrichissement** (MITRE/EPSS)
est activé (`OFFLINE_ONLY = False`), tout accès passe par
`http_client.get_json()` qui garantit :

- **Rate limiting** : `REQUEST_DELAY = 2.0` s avant chaque appel réseau réel.
- **Cache disque** sous `data/cache/` : une réponse déjà téléchargée n'est pas
  redemandée. Une CVE partagée par plusieurs bulletins n'est enrichie qu'une fois
  (cache mémoire dans `pipeline.run`).
- **Robustesse** : retry avec backoff sur erreurs réseau / `429` / `5xx`, et
  retour `None` propre (jamais d'exception remontée) pour ne pas casser le run.

## Format du CSV consolidé

Une ligne par couple (bulletin × CVE) — un bulletin multi-CVE est donc répété.

| Colonne | Description |
|---|---|
| `id_anssi` | Identifiant du bulletin (ex. `CERTFR-2024-ALE-001`) |
| `titre_anssi` | Titre de l'avis ou de l'alerte |
| `type_bulletin` | `Avis` ou `Alerte` |
| `date_publication` | Date de publication ANSSI |
| `cve_id` | Identifiant CVE |
| `score_cvss` | Score CVSS (0-10), vide si indisponible |
| `base_severity` | Gravité : Faible / Moyenne / Élevée / Critique |
| `type_cwe` | Identifiant CWE (ex. `CWE-287`) |
| `score_epss` | Probabilité d'exploitation (0-1) |
| `lien_bulletin` | URL du bulletin ANSSI |
| `description` | Description de la vulnérabilité (MITRE) |
| `editeur` | Éditeur(s) du produit affecté |
| `produit` | Produit(s) affecté(s) |
| `versions_affectees` | Versions impactées |

**Choix de modélisation** : éditeur / produit / versions sont issus de
l'enrichissement MITRE. Une CVE pouvant concerner plusieurs produits, les
valeurs distinctes sont concaténées avec `" ; "` afin de conserver une seule
ligne par couple (bulletin × CVE). Les champs absents valent `Non disponible`.

## Web app Django (étape 7 — « Pour aller loin », bonus)

Application web qui rend le `consolidated.csv` **consultable et exploitable** par un
public non expert. Les données sont chargées dans **SQLite via l'ORM Django**, avec un
**schéma normalisé** `Bulletin` ↔ `Cve` en Many-to-Many (cf.
`vulnerabilities/models.py`) : l'enrichissement étant identique pour un même `cve_id`,
on évite ainsi de dupliquer les descriptions et on répond à « cette CVE apparaît dans
N bulletins ».

### Fonctionnalités

- **Tableau de bord** (`/`) : 4 indicateurs clés (failles suivies, bulletins, failles
  critiques, alertes) + **8 graphiques Plotly interactifs** reprenant les visualisations
  de l'étape 5 — distribution CVSS, répartition par gravité, camembert CWE (top 10),
  courbe EPSS triée (échelle log), top 15 éditeurs, nuage CVSS × EPSS, **avis vs alertes
  par éditeur**, et CVE cumulées dans le temps.
- **Listes filtrables & triables** : CVE (recherche, gravité, éditeur, CVSS min, EPSS
  min, année) et bulletins (recherche, type, année) — **colonnes triables** (▲/▼) et
  **pagination**.
- **Pages de détail** : une CVE (avec les bulletins qui la citent) et un bulletin (avec
  ses CVE).
- **Page d'alertes** (`/alertes/`) : critère `CVSS ≥ 9` **OU** `EPSS ≥ 0.5` (même règle
  que le notebook, cf. `vulnerabilities/alerts.py`), **filtrable par éditeur / produit /
  type / année** — la veille « sur mesure » du sujet, avec un **aperçu d'email recalculé
  sur la sélection**.
- **Export CSV** des résultats filtrés (CVE et alertes), généré en **streaming**
  (`StreamingHttpResponse`) pour tenir la volumétrie.
- **Glossaire pédagogique** : termes techniques (CVE, CVSS, EPSS, CWE, CERT-FR, ANSSI…)
  expliqués en **infobulles** au survol ; interface **Bootstrap 5** responsive.

```
webapp/
  manage.py
  anssi_web/         # projet Django (settings, urls, wsgi/asgi)
  vulnerabilities/   # app principale
    models.py            # schéma normalisé Bulletin ↔ Cve (M2M)
    views.py, urls.py    # vues (dashboard, listes, détails, alertes, exports) + routes
    charts.py            # 8 graphiques Plotly du tableau de bord
    alerts.py            # critère d'alerte (CVSS≥9 OU EPSS≥0.5) + génération d'email
    admin.py, apps.py
    templatetags/        # glossary (infobulles) + sort_tags (colonnes triables)
    management/commands/import_csv.py   # charge data/consolidated.csv → SQLite (idempotent)
    migrations/          # schéma initial
    templates/vulnerabilities/          # base + dashboard + listes/détails + alertes
```

Lancement (après avoir généré `data/consolidated.csv` via le pipeline) :

```bash
uv run python webapp/manage.py migrate        # crée la base SQLite
uv run python webapp/manage.py import_csv      # importe le CSV consolidé (commande idempotente)
uv run python webapp/manage.py runserver       # http://127.0.0.1:8000/
```

Routes : `/` (tableau de bord, accessible sans connexion), `/cve/` (liste CVE),
`/cve/<CVE-ID>/`, `/cve/export.csv` (export CSV filtré), `/bulletins/`,
`/bulletins/<ID-ANSSI>/`, `/alertes/`, `/alertes/export.csv` (export CSV filtré).

### Accès à l'interface d'administration (`/admin/`)

Distincte du tableau de bord : `/admin/` est l'interface Django standard de
consultation brute des tables (`Cve`, `Bulletin`) avec recherche, filtres et
tri — pas les graphiques. Elle nécessite un compte superutilisateur, à créer
une seule fois :

```bash
uv run python webapp/manage.py createsuperuser
```

Renseigner un nom d'utilisateur, un email (optionnel) et un mot de passe
(saisie interactive, invisible). Se connecter ensuite sur
`http://127.0.0.1:8000/admin/` avec ces identifiants.

La base `webapp/db.sqlite3` est régénérable et n'est pas versionnée ; relancer
`import_csv` la recharge (commande idempotente), sans toucher au compte admin.

## Points de vigilance

- **Volumétrie du CSV** : avec `DEFAULT_YEARS = None`, `consolidated.csv` peut
  peser **plusieurs centaines de Mo**. Restreindre les années (`config.py`) pour
  un livrable plus léger ou des essais rapides.
- **Mode hors-ligne par défaut** : `OFFLINE_ONLY = True` n'émet aucun appel
  réseau ; une CVE absente du dump reste `Non disponible`. Mettre `False`
  seulement si l'on veut compléter via les API (alors soumis au rate-limiting).
- **Ordre des étapes** : la web app et le notebook **dépendent du CSV** — lancer
  le pipeline (étape 1) **avant** `import_csv` ou l'exécution du notebook.
- **Données non versionnées** : `data/` et `webapp/db.sqlite3` sont régénérables
  et hors Git. Pour le rendu, **inclure `data/consolidated.csv` manuellement**
  dans l'archive.
- **Export HTML** : faire **Restart & Run All** (ou `nbconvert --execute`) avant
  l'export pour que `notebook.html` reflète les dernières sorties.
- **Envoi d'email désactivé** : conformément au sujet, seuls le **sujet** et le
  **corps** de l'alerte sont générés ; l'envoi SMTP n'est pas appelé (éviter
  d'exposer des identifiants).
