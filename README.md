# Analyse des avis et alertes ANSSI avec enrichissement des CVE

Pipeline Python qui extrait les bulletins de sécurité du CERT-FR (ANSSI),
identifie les CVE référencées, les enrichit via les API **MITRE** (CVSS, CWE) et
**EPSS/FIRST** (probabilité d'exploitation), puis consolide le tout dans un
fichier CSV exploitable.

> Périmètre actuel : **étapes 1 à 4** du sujet (extraction → enrichissement →
> consolidation → CSV). Les visualisations (étape 5), le Machine Learning
> (étape 6) et les alertes email (étape 7) seront ajoutés dans le notebook à
> partir du CSV produit.

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
`data/mitre/`, `data/first/`) et écrit `data/consolidated.csv`. Aucun appel
réseau n'est nécessaire si le dump couvre tous les bulletins/CVE (~36 s pour
les 4 103 bulletins / 37 287 CVE fournis).

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
