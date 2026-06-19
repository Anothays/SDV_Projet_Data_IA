"""Configuration Django de la web app ANSSI/CVE (étape 7, bonus du sujet).

Application de démonstration : expose le `data/consolidated.csv` (étapes 1-4)
sous forme de tableau de bord, de listes filtrables et d'alertes critiques.
Configuration volontairement orientée *dev/démo* (SQLite, DEBUG=True) ; aucun
durcissement production n'est visé ici (cf. « Hors périmètre » du plan).
"""

from pathlib import Path

# BASE_DIR = dossier webapp/ (parent de ce package anssi_web).
BASE_DIR = Path(__file__).resolve().parent.parent

# Clé de dev : suffisante pour une démo locale, à régénérer pour un vrai déploiement.
SECRET_KEY = "django-insecure-anssi-cve-demo-key-change-me"

# Démo locale : DEBUG actif et hôtes ouverts (jamais en production).
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "vulnerabilities",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "anssi_web.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "anssi_web.wsgi.application"

# Base SQLite locale (suffisante pour ~126 k liens / ~37 k CVE).
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Localisation française (projet SUP DE VINCI).
LANGUAGE_CODE = "fr-fr"
TIME_ZONE = "Europe/Paris"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
