"""Configuration de l'app Django ``vulnerabilities``."""

from django.apps import AppConfig


class VulnerabilitiesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "vulnerabilities"
    verbose_name = "Vulnérabilités ANSSI/CVE"
