#!/bin/bash
set -e

# Apply database migrations
python manage.py migrate --noinput

# Launch production Gunicorn WSGI server
exec gunicorn --bind=0.0.0.0:8000 --workers=4 --threads=2 --timeout=600 Email_Phisher.wsgi:application
