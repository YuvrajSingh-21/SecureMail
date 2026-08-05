# SecuraMail Production Deployment Guide

## 1. System Requirements

- **Operating System**: Ubuntu 22.04 LTS or 24.04 LTS
- **Python**: Python 3.11, 3.12, or 3.14
- **Database Engine**: PostgreSQL 15 or 16
- **Reverse Proxy**: Nginx 1.24+
- **WSGI Application Server**: Gunicorn 21.0+
- **Memory**: Minimum 4 GB RAM (8 GB+ recommended for high-volume ATAE processing)

---

## 2. Infrastructure Setup

### 2.1 PostgreSQL Configuration
```bash
sudo apt update && sudo apt install -y postgresql postgresql-contrib libpq-dev
sudo -u postgres psql -c "CREATE DATABASE securemail_db;"
sudo -u postgres psql -c "CREATE USER securemail_user WITH PASSWORD 'SECURE_DB_PASSWORD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE securemail_db TO securemail_user;"
```

### 2.2 Python Virtual Environment & Dependencies
```bash
cd /opt/securemail
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn
```

---

## 3. Environment Configuration (`.env`)

Create `/opt/securemail/.env`:
```ini
DEBUG=False
SECRET_KEY=generate-a-cryptographically-secure-50-character-secret-key
ENCRYPTION_KEY=generate-a-32-byte-base64-aes-key

# Database
DB_NAME=securemail_db
DB_USER=securemail_user
DB_PASSWORD=SECURE_DB_PASSWORD
DB_HOST=127.0.0.1
DB_PORT=5432

# Google OAuth Credentials
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/callback/

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your-virustotal-v3-api-key
SAFE_BROWSING_API_KEY=your-google-safe-browsing-api-key
GEMINI_API_KEY=your-gemini-pro-api-key

# Host Security
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

---

## 4. Gunicorn Systemd Service

Create `/etc/systemd/system/securemail.service`:
```ini
[Unit]
Description=SecuraMail Gunicorn Daemon
After=network.target postgresql.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/securemail
EnvironmentFile=/opt/securemail/.env
ExecStart=/opt/securemail/venv/bin/gunicorn \
          --workers 4 \
          --threads 2 \
          --bind unix:/run/securemail.sock \
          --access-logfile /var/log/securemail/gunicorn_access.log \
          --error-logfile /var/log/securemail/gunicorn_error.log \
          Email_Phisher.wsgi:application

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
sudo mkdir -p /var/log/securemail
sudo chown -R www-data:www-data /var/log/securemail
sudo systemctl daemon-reload
sudo systemctl enable --now securemail
```

---

## 5. Nginx Reverse Proxy Configuration

Create `/etc/nginx/sites-available/securemail`:
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "same-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location /static/ {
        alias /opt/securemail/staticfiles/;
        expires 30d;
    }

    location /media/ {
        alias /opt/securemail/media/;
        internal;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/run/securemail.sock;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/securemail /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 6. Pre-Flight Production Checklist

- [ ] `DEBUG=False` verified in `.env`.
- [ ] Database migrations executed: `python manage.py migrate`.
- [ ] Static assets collected: `python manage.py collectstatic --noinput`.
- [ ] SSL certificate active via Let's Encrypt Certbot.
- [ ] Gunicorn socket permissions verified (`/run/securemail.sock`).
- [ ] Daily PostgreSQL backup cron configured via `pg_dump`.
