# AGENT.md — Onboarding agent IA

Document d'entrée pour tout agent IA travaillant sur ce dépôt. Lis-le en entier
avant d'agir.

## 1. But du projet

TD final noté (SUP DE VINCI, Data & IA 2026). Construire un outil qui :

1. Extrait les bulletins de sécurité du **CERT-FR / ANSSI** (avis + alertes), depuis le **dump local fourni** (`data/Avis/`, `data/alertes/`) en priorité, flux RSS en repli.
2. Identifie les **CVE** (Common Vulnerabilities and Exposures) citées dans chaque bulletin.
3. Enrichit chaque CVE, depuis le dump local (`data/mitre/`, `data/first/`) en priorité, API en repli :
   - **MITRE** (`cveawg.mitre.org`) → score **CVSS** (gravité 0-10), type **CWE** (nature de la faille), description, produits affectés.
   - **EPSS / FIRST** (`api.first.org`) → **score EPSS** (probabilité d'exploitation, 0-1).
4. Consolide le tout dans un **DataFrame pandas** exporté en **CSV**.
5. *(à venir)* Visualise et analyse les données.
6. *(à venir)* Applique du **Machine Learning** (≥ 1 modèle supervisé + 1 non supervisé).
7. *(à venir)* Génère des **alertes email** personnalisées.

Contexte métier : l'ANSSI ne fournit (contrairement au NIST) ni statistiques ni
alertes sur mesure. Cet outil comble ce manque en automatisant l'extraction,
l'enrichissement et l'analyse.

## 2. Périmètre actuel vs reste à faire

| Étape | Sujet | État |
|---|---|---|
| 1 | Lecture bulletins (dump local `data/Avis/` + `data/alertes/`) | ✅ fait (`local_source.py`) |
| 2 | Extraction CVE | ✅ fait (`cve_extraction.py`) |
| 3 | Enrichissement MITRE + EPSS (dump local `data/mitre/` + `data/first/`) | ✅ fait (`enrichment.py`) |
| 4 | Consolidation → CSV | ✅ fait (`consolidation.py`, `pipeline.py`) |
| 5 | Visualisation / analyse | ✅ fait (`notebook.ipynb`, 11 visualisations) |
| 6 | Machine Learning + validation | ✅ fait (`notebook.ipynb` : RandomForest gravité + KMeans) |
| 7 | Alertes & notifications email | ✅ fait (`notebook.ipynb` : sujet + corps ; envoi SMTP optionnel non appelé) |

**Changement de plan (2026-06-18)** : le sujet fournit désormais un dump local
complet (`data/Avis/`, `data/alertes/`, `data/mitre/`, `data/first/`, un
fichier par bulletin/CVE sans extension). Le pipeline lit ce dump en
priorité — `rss.py` et les appels réseau live (MITRE/EPSS) ne servent plus
que de repli pour un bulletin/CVE absent du dump. Voir `local_source.py` et
section 5 ci-dessous.

**Modèles ML retenus (2026-06-18)** : supervisé = classification de
`base_severity` par RandomForest, *sans* `score_cvss` en variable (fuite de
cible : la gravité en est dérivée) → features `score_epss` + `type_cwe` +
`type_bulletin` + `editeur`. Non supervisé = KMeans sur (`score_cvss`,
`score_epss`) pour des profils de risque. Validation : `classification_report`
+ matrice de confusion + cross-val (F1-macro) ; coude + silhouette pour KMeans.

**Périmètre / config** : `OFFLINE_ONLY = True` (aucun réseau) et
`DEFAULT_YEARS = None` (dump local complet, 2021-2026 — c'est le périmètre
du `consolidated.csv` livré et du notebook). Le notebook est construit par
`build_notebook.py` puis exécuté ; export `notebook.html`.

**Livraison (2026-06-18)** : remise sous forme d'**archive** au professeur,
pas via push git — `data/consolidated.csv` (exclu de `.gitignore`, comme
tout `data/*`) doit donc être inclus manuellement dans l'archive envoyée.

## 3. Architecture

```
src/anssi_cve/
  config.py          # URLs des feeds/API, délais, chemins (live + dump local)
  http_client.py     # accès réseau responsable : rate-limit + retry + cache disque (repli)
  local_source.py    # étape 1 : lecture data/Avis + data/alertes → liste de bulletins (JSON déjà inclus)
  rss.py             # variante live (flux RSS), non utilisée par défaut depuis le dump local
  cve_extraction.py  # étape 2 : JSON du bulletin → liste de CVE
  enrichment.py      # étape 3 : enrich_mitre() + enrich_epss(), dump local puis API (défensifs)
  consolidation.py   # étape 4 : build_dataframe(), severity_from_cvss(), COLUMNS
  pipeline.py         # orchestration end-to-end → data/consolidated.csv
data/
  Avis/, alertes/    # dump local des bulletins ANSSI (fourni, section 8 du sujet)
  mitre/, first/     # dump local des réponses API CVE/EPSS (fourni)
  cache/             # cache JSON du repli réseau (bulletins/, mitre/, first/) — non versionné
  consolidated.csv   # livrable 2 (généré)
main.py              # point d'entrée → anssi_cve.pipeline.run()
notebook.ipynb       # réservé aux étapes 5-6 (chargera le CSV) — ne pas y mettre le pipeline
```

Flux de données : `local_source` (lecture `data/Avis`+`data/alertes`, JSON déjà
chargé) → `cve_extraction` (CVE) → `enrichment` (MITRE + EPSS, dump local puis
API en repli) → `consolidation` (1 ligne par couple bulletin × CVE) → CSV.

## 4. Conventions du dépôt (à respecter)

- **Langue** : commentaires/docstrings/doc en **français**. Code et identifiants en anglais quand naturel.
- **Style** : clean code, SOLID, **défensif** — un champ d'API absent ne doit JAMAIS lever une exception qui casse le run ; renvoyer `None` (numérique) ou `"Non disponible"` (texte). Voir `enrichment.UNAVAILABLE` et le helper `_clean`.
- **Commits** : conventionnels en anglais (`feat:`, `fix:`, `chore:`). **Ne jamais committer sans confirmation de l'utilisateur.**
- **Pas de reformatage** global (Prettier non configuré ici).
- **Gestionnaire de paquets** : `uv` (Python ≥ 3.13). Dépendances déclarées dans `pyproject.toml`. Package en src-layout (hatchling).

## 5. Accès responsable aux ressources externes (section 8 du sujet — IMPORTANT)

Le dump local fourni par l'enseignant (`data/Avis/`, `data/alertes/`,
`data/mitre/`, `data/first/`) est **prioritaire** : `local_source.py` et
`enrichment._read_local` lisent ces fichiers directement, sans aucun appel
réseau. Le réseau ne sert plus que de **repli** pour un bulletin ou une CVE
absente du dump (cas peu probable, dump quasi complet : 4103 bulletins /
37287 CVE).

Tout accès réseau (repli) **doit** passer par `http_client.get_json()`. Ne pas appeler
`requests` directement ailleurs. Garanties fournies :

- **Rate-limiting** : `REQUEST_DELAY = 2.0 s` (config) appliqué avant chaque appel réseau réel.
- **Cache disque** sous `data/cache/` : une ressource déjà téléchargée n'est pas redemandée. Une CVE partagée par plusieurs bulletins n'est enrichie qu'une fois (cache mémoire dans `pipeline.run`).
- **Retry + backoff** sur erreurs réseau / `429` / `5xx`.

Ne pas retirer ce repli réseau : il garde le pipeline correct si le dump est
incomplet ou si de nouveaux bulletins/CVE apparaissent après l'extraction du
dump.

## 6. Lancer / vérifier

```bash
uv sync                              # installer deps + package
uv run python -m anssi_cve.pipeline  # exécuter le pipeline → data/consolidated.csv
```

Run typique : ~36 s pour 4103 bulletins / 37287 CVE, zéro appel réseau (tout
vient du dump local). Plus lent uniquement si des bulletins/CVE manquent au
dump (repli réseau avec délai 2 s).
Vérifications attendues :
- CSV avec les 14 colonnes de `consolidation.COLUMNS`.
- ≥ 1 ligne par bulletin, plusieurs lignes pour un bulletin multi-CVE.
- `base_severity` cohérente avec `score_cvss` ; `score_epss` ∈ [0,1] ou vide.
- Aucune exception sur une CVE sans champ CVSS.

## 7. Schéma du CSV consolidé

Une ligne = un couple (bulletin × CVE). Colonnes (ordre figé dans `COLUMNS`) :

`id_anssi`, `titre_anssi`, `type_bulletin` (Avis|Alerte), `date_publication`,
`cve_id`, `score_cvss`, `base_severity` (Faible|Moyenne|Élevée|Critique),
`type_cwe`, `score_epss`, `lien_bulletin`, `description`, `editeur`, `produit`,
`versions_affectees`.

Éditeur/produit/versions issus de MITRE ; valeurs multiples concaténées par `" ; "`.

## 8. Livrables & échéances

- **Livrable 1** : code Python fonctionnel + README. *(en place)*
- **Livrable 2** : `data/consolidated.csv`. *(généré par le pipeline)*
- **Livrable 3** : `notebook.ipynb` + export **HTML** — chargement du CSV, exploration, visualisations variées, ML (1 supervisé + 1 non supervisé) + validation. *(à faire)*
- Équipes de 3. Dépôt : **vendredi 19 juin 2026, 14h30**. Peer review jusqu'au **mardi 23 juin 2026, 23h**.
- Feuille de participation par membre (ratio %) à remettre avant présentation.

## 9. Pièges connus

- Les réponses MITRE renvoient souvent `"n/a"` (chaîne) pour vendor/product → normalisé via `enrichment._clean`.
- Le score CVSS peut être absent, ou dans une version différente (`cvssV3_1`, `cvssV3_0`, `cvssV4_0`, `cvssV2`) et parfois dans le conteneur `adp` plutôt que `cna` → géré par `_iter_metrics` + `_extract_cvss`.
- L'identifiant ANSSI se lit dans le lien RSS (regex `CERTFR-AAAA-(ALE|AVI)-NNN`) ou la clé `reference` du JSON.
- L'URL JSON d'un bulletin = lien du bulletin + `json/`.
- Plagiat surveillé : le travail doit rester authentique (contrainte du sujet).
