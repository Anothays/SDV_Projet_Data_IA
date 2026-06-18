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

# Sous-dossiers de cache par type de ressource (utilisés pour les CVE/bulletins
# absents du jeu de données local, cf. ci-dessous).
CACHE_BULLETIN_DIR = CACHE_DIR / "bulletins"  # JSON des avis/alertes ANSSI
CACHE_MITRE_DIR = CACHE_DIR / "mitre"          # réponses API MITRE
CACHE_FIRST_DIR = CACHE_DIR / "first"          # réponses API EPSS/FIRST

# --- Jeu de données pré-téléchargé (section 8 du sujet) ---
# Fourni par le prof : un fichier par bulletin/CVE, sans extension, au format
# JSON identique à celui des API live. Utilisé en priorité pour éviter de
# solliciter les serveurs externes ; le réseau ne sert que de repli pour les
# bulletins/CVE absents de ce dump.
LOCAL_AVIS_DIR = DATA_DIR / "Avis"
LOCAL_ALERTES_DIR = DATA_DIR / "alertes"
LOCAL_MITRE_DIR = DATA_DIR / "mitre"
LOCAL_FIRST_DIR = DATA_DIR / "first"

# Si True, on n'interroge JAMAIS le réseau : le dump local fait foi (une CVE
# absente du dump est simplement marquée "Non disponible"). Évite des timeouts
# coûteux hors-ligne et garantit l'accès responsable (section 8) lors du run
# complet sur ~4100 bulletins.
OFFLINE_ONLY = True

# Périmètre par défaut du CSV consolidé : on borne aux bulletins récents pour
# garder un livrable de taille raisonnable (le dump complet ~4100 bulletins
# produit un CSV de ~170 Mo). Mettre None pour tout traiter.
DEFAULT_YEARS = (2024, 2025, 2026)
