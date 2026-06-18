# AGENT.md — Onboarding agent IA

Document d'entrée pour tout agent IA travaillant sur ce dépôt. Lis-le en entier
avant d'agir.

## 1. But du projet

TD final noté (SUP DE VINCI, Data & IA 2026). Construire un outil qui :

1. Extrait les bulletins de sécurité du **CERT-FR / ANSSI** (avis + alertes) via flux RSS.
2. Identifie les **CVE** (Common Vulnerabilities and Exposures) citées dans chaque bulletin.
3. Enrichit chaque CVE via API externes :
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
| 1 | Extraction flux RSS | ✅ fait (`rss.py`) |
| 2 | Extraction CVE | ✅ fait (`cve_extraction.py`) |
| 3 | Enrichissement MITRE + EPSS | ✅ fait (`enrichment.py`) |
| 4 | Consolidation → CSV | ✅ fait (`consolidation.py`, `pipeline.py`) |
| 5 | Visualisation / analyse | ⏳ à faire (notebook) |
| 6 | Machine Learning + validation | ⏳ à faire (modèles non encore choisis — à déduire de l'analyse exploratoire) |
| 7 | Alertes & notifications email | ⏳ à faire (optionnel pour l'envoi, mais sujet + corps du mail attendus) |

**Décision en attente** : choix des modèles ML. À trancher *après* l'analyse
exploratoire des données du CSV, pas avant.

## 3. Architecture

```
src/anssi_cve/
  config.py          # URLs des feeds/API, délais, chemins (source de vérité config)
  http_client.py     # accès réseau responsable : rate-limit + retry + cache disque
  rss.py             # étape 1 : flux RSS avis + alertes → liste de bulletins
  cve_extraction.py  # étape 2 : JSON du bulletin → liste de CVE
  enrichment.py      # étape 3 : enrich_mitre() + enrich_epss() (défensifs)
  consolidation.py   # étape 4 : build_dataframe(), severity_from_cvss(), COLUMNS
  pipeline.py        # orchestration end-to-end → data/consolidated.csv
data/
  cache/             # cache JSON (bulletins/, mitre/, first/) — non versionné
  consolidated.csv   # livrable 2 (généré)
main.py              # point d'entrée → anssi_cve.pipeline.run()
notebook.ipynb       # réservé aux étapes 5-6 (chargera le CSV) — ne pas y mettre le pipeline
```

Flux de données : `rss` → liens bulletins → `cve_extraction` (JSON) → CVE →
`enrichment` (MITRE + EPSS) → `consolidation` (1 ligne par couple bulletin × CVE) → CSV.

## 4. Conventions du dépôt (à respecter)

- **Langue** : commentaires/docstrings/doc en **français**. Code et identifiants en anglais quand naturel.
- **Style** : clean code, SOLID, **défensif** — un champ d'API absent ne doit JAMAIS lever une exception qui casse le run ; renvoyer `None` (numérique) ou `"Non disponible"` (texte). Voir `enrichment.UNAVAILABLE` et le helper `_clean`.
- **Commits** : conventionnels en anglais (`feat:`, `fix:`, `chore:`). **Ne jamais committer sans confirmation de l'utilisateur.**
- **Pas de reformatage** global (Prettier non configuré ici).
- **Gestionnaire de paquets** : `uv` (Python ≥ 3.13). Dépendances déclarées dans `pyproject.toml`. Package en src-layout (hatchling).

## 5. Accès responsable aux ressources externes (section 8 du sujet — IMPORTANT)

Tout accès réseau **doit** passer par `http_client.get_json()`. Ne pas appeler
`requests` directement ailleurs. Garanties fournies :

- **Rate-limiting** : `REQUEST_DELAY = 2.0 s` (config) appliqué avant chaque appel réseau réel.
- **Cache disque** sous `data/cache/` : une ressource déjà téléchargée n'est pas redemandée. Une CVE partagée par plusieurs bulletins n'est enrichie qu'une fois (cache mémoire dans `pipeline.run`).
- **Retry + backoff** sur erreurs réseau / `429` / `5xx`.

Le sujet prévoit aussi des **snapshots locaux pré-téléchargés** (`alertes/`,
`avis/`, `mitre/`, `first/`) éventuellement fournis par l'enseignant. S'ils
arrivent, le cache local joue déjà ce rôle ; l'approche (consulter les feeds,
repérer les mises à jour) ne doit pas changer.

## 6. Lancer / vérifier

```bash
uv sync                              # installer deps + package
uv run python -m anssi_cve.pipeline  # exécuter le pipeline → data/consolidated.csv
```

Premier run : lent (délai 2 s + téléchargements). Runs suivants : rapides (cache).
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
