"""Point d'entrée WSGI de la web app ANSSI/CVE."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "anssi_web.settings")

application = get_wsgi_application()
