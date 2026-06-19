# Analyse des avis et alertes ANSSI avec enrichissement des CVE

Pipeline Python qui extrait les bulletins de sécurité du CERT-FR (ANSSI),
identifie les CVE référencées, les enrichit via les API **MITRE** (CVSS, CWE) et
**EPSS/FIRST** (probabilité d'exploitation), puis consolide le tout dans un
fichier CSV exploitable.

> Périmètre : **étapes 1 à 7** du sujet. Le pipeline (`src/anssi_cve/`) couvre
> l'extraction → l'enrichissement → la consolidation → le CSV. Le notebook
> (`notebook.ipynb`, exporté en `notebook.html`) couvre l'exploration et les
> visualisations (étape 5), le Machine Learning (étape 6) et la génération
> d'alertes email (étape 7) à partir du CSV produit.

## Source des données

Le pipeline lit en priorité le **dump local fourni** (section 8 du sujet,
`data/Avis/`, `data/alertes/`, `data/mitre/`, `data/first/`) plutôt que
d'interroger les flux RSS et API en direct : zéro latence, zéro charge sur
les serveurs externes. Le réseau (avec rate-limiting) ne sert qu'en repli
pour une CVE absente du dump.

## Architecture

```
src/anssi_cve/
  config.py          # URLs, délais, chemins (live + dump local)
  http_client.py     # repli réseau responsable : rate-limit + retry + cache disque
  local_source.py    # étape 1+2 : lecture des bulletins depuis data/Avis + data/alertes
  rss.py              # variante live (flux RSS), non utilisée par défaut
  cve_extraction.py  # étape 2 : CVE référencées dans chaque bulletin
  enrichment.py      # étape 3 : enrichissement MITRE (CVSS/CWE) + EPSS, local puis API
  consolidation.py   # étape 4 : DataFrame pandas (1 ligne par couple bulletin × CVE)
  pipeline.py         # orchestration end-to-end → data/consolidated.csv
data/
  Avis/, alertes/    # dump local des bulletins ANSSI (fourni)
  mitre/, first/     # dump local des réponses API CVE/EPSS (fourni)
  cache/             # cache JSON des appels réseau de repli (régénérable, non versionné)
  consolidated.csv   # livrable : données consolidées
main.py              # point d'entrée
```

## Installation

Projet géré avec [uv](https://docs.astral.sh/uv/) (Python ≥ 3.13).

```bash
uv sync
```

## Lancement

```bash
uv run python -m anssi_cve.pipeline   # ou : uv run python main.py
```

Le pipeline lit le dump local fourni (`data/Avis/`, `data/alertes/`,
`data/mitre/`, `data/first/`) et écrit `data/consolidated.csv`. Par défaut
`config.OFFLINE_ONLY = True` : **aucun appel réseau** n'est émis (une CVE
absente du dump est marquée `Non disponible`). Par défaut
`config.DEFAULT_YEARS = None` : tout le dump local est traité (~4100
bulletins, 2021-2026), soit le CSV livré (~170 Mo) ; passer un tuple
d'années (ex. `(2024, 2025, 2026)`) pour restreindre le périmètre.

Puis, pour les étapes 5-7 et le livrable HTML :

```bash
uv run jupyter nbconvert --to notebook --execute --inplace notebook.ipynb
uv run jupyter nbconvert --to html notebook.ipynb        # → notebook.html
```

> `notebook.ipynb` est généré par `build_notebook.py` (script de construction
> reproductible des cellules) puis exécuté ; on peut aussi l'ouvrir et le
> relancer directement dans Jupyter.

## Accès responsable aux ressources externes

Conformément à la section 8 du sujet, le code reste capable d'aller chercher
en direct un bulletin ou une CVE absente du dump local :

- **Rate limiting** : `REQUEST_DELAY = 2.0` s appliqué avant chaque appel réseau
  (`http_client._respect_delay`).
- **Cache disque** : chaque réponse JSON (bulletins, MITRE, EPSS) est mise en
  cache sous `data/cache/`. Une CVE partagée par plusieurs bulletins n'est
  interrogée qu'une seule fois (cache mémoire dans `pipeline.run`).
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

Application web qui rend le `consolidated.csv` consultable : **tableau de bord**
de graphiques interactifs (Plotly), **listes filtrables** de CVE et de bulletins
avec pages de détail, et **page d'alertes** critiques (mêmes critères que le
notebook : `CVSS ≥ 9` ou `EPSS ≥ 0.5`). Les données sont chargées dans **SQLite
via l'ORM Django** (schéma normalisé `Bulletin` ↔ `Cve`).

```
webapp/
  manage.py
  anssi_web/         # projet Django (settings, urls, wsgi/asgi)
  vulnerabilities/   # app : models, views, charts (Plotly), alerts, admin
    management/commands/import_csv.py   # charge data/consolidated.csv → SQLite
    templates/vulnerabilities/          # base + dashboard + listes/détails + alertes
```

Lancement (après avoir généré `data/consolidated.csv` via le pipeline) :

```bash
uv run python webapp/manage.py migrate        # crée la base SQLite
uv run python webapp/manage.py import_csv      # importe le CSV (~126k liens)
uv run python webapp/manage.py runserver       # http://127.0.0.1:8000/
```

Routes : `/` (tableau de bord, accessible sans connexion), `/cve/` (liste CVE),
`/cve/<CVE-ID>/`, `/bulletins/`, `/bulletins/<ID-ANSSI>/`, `/alertes/`.

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
