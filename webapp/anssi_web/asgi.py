"""Point d'entrée ASGI de la web app ANSSI/CVE."""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "anssi_web.settings")

application = get_asgi_application()
