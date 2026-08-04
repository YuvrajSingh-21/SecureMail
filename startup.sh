#!/bin/bash
set -e

python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec gunicorn \
    --bind=0.0.0.0:8000 \
    --workers=4 \
    --threads=2 \
    --timeout=600 \
    Email_Phisher.wsgi:application