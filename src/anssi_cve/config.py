"""Configuration centralisée du pipeline (URLs, délais, chemins)."""

from pathlib import Path

# --- Flux RSS CERT-FR (étape 1) ---
FEED_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
FEED_ALERTE = "https://www.cert.ssi.gouv.fr/alerte/feed/"

# --- API d'enrichissement (étape 3) ---
MITRE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={cve_id}"

# --- Accès responsable aux ressources externes (section 8 du sujet) ---
# Délai minimal entre deux appels réseau, en secondes.
REQUEST_DELAY = 2.0
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
USER_AGENT = "SUPDEVINCI-DataIA-Project/1.0 (educational; CERT-FR analysis)"

# --- Chemins de sortie ---
ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
CACHE_DIR = DATA_DIR / "cache"
OUTPUT_CSV = DATA_DIR / "consolidated.csv"

# Sous-dossiers de cache par type de ressource.
CACHE_BULLETIN_DIR = CACHE_DIR / "bulletins"  # JSON des avis/alertes ANSSI
CACHE_MITRE_DIR = CACHE_DIR / "mitre"          # réponses API MITRE
CACHE_FIRST_DIR = CACHE_DIR / "first"          # réponses API EPSS/FIRST
