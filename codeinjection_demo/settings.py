"""
Minimal Django settings for the code injection teaching demo.

NOTE: This project is intentionally simple and intentionally insecure in
places (see vulnapp/views.py). It is for a local, offline classroom demo
only. Do not deploy this anywhere reachable over a network.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Fine for a throwaway local teaching demo only - never do this in real projects.
SECRET_KEY = "django-insecure-demo-key-not-for-production"

DEBUG = True

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "vulnapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

ROOT_URLCONF = "codeinjection_demo.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
            ],
        },
    },
]

WSGI_APPLICATION = "codeinjection_demo.wsgi.application"

# No database needed for this demo.
DATABASES = {}

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
