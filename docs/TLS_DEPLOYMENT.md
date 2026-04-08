# TLS Deployment Guide

AI Guardian speaks **HTTP only** by design. It does not handle TLS termination. You MUST deploy it behind a TLS-terminating reverse proxy in production.

This document covers:
- Why TLS proxy is required
- nginx reverse proxy configuration
- Caddy reverse proxy configuration
- Docker Compose with embedded proxy (optional)

---

## Why AI Guardian Does Not Handle TLS

- Simpler, more focused application code
- TLS certificates are infrastructure concerns (managed by ops/DevOps)
- Proxy handles cert renewal (Let's Encrypt, etc.)
-符合 12-factor app principles

---

## Architecture

```
Internet → TLS (443) → Reverse Proxy → AI Guardian (:8000)
                                        (HTTP only)
```

---

## nginx Configuration

```nginx
# /etc/nginx/sites-available/ai-guardian

server {
    listen 80;
    server_name ai-guardian.yourdomain.com;
    return 301 https://$host$request_uri;  # Redirect HTTP → HTTPS
}

server {
    listen 443 ssl http2;
    server_name ai-guardian.yourdomain.com;

    # TLS certificates (managed by certbot / Let's Encrypt)
    ssl_certificate     /etc/letsencrypt/live/ai-guardian.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ai-guardian.yourdomain.com/privkey.pem;
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_ciphers          HIGH:!aNULL:!MD5:!RC4;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;

        # Forward real client IP
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        # Timeouts
        proxy_read_timeout 60s;
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;

        # Do NOT proxy WebSocket upgrades here unless needed
        # AI Guardian does not currently use WebSockets
    }
}
```

### Install and Enable

```bash
# Install nginx + certbot
sudo apt install nginx certbot python3-certbot-nginx

# Obtain TLS certificate (interactive)
sudo certbot --nginx -d ai-guardian.yourdomain.com

# Test nginx config
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

---

## Caddy Configuration (Simpler)

Caddy handles TLS automatically with Let's Encrypt.

```caddy
# /etc/caddy/Caddyfile

ai-guardian.yourdomain.com {
    reverse_proxy localhost:8000

    # Optional: custom log
    log {
        output file /var/log/caddy/ai-guardian.log
    }
}
```

```bash
# Install Caddy
sudo apt install -y apt-transport-https
sudo curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-archive-keyring.gpg
sudo curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy

# Start Caddy
sudo caddy fmt --overwrite /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
```

---

## Docker Compose with Caddy (Optional)

For simple deployments, use the `with-caddy` variant:

```yaml
# docker-compose.with-caddy.yml
services:
  ai-guardian:
    build: .
    restart: unless-stopped
    environment:
      AI_GUARDIAN_BOOTSTRAP_KEYS: ${AI_GUARDIAN_BOOTSTRAP_KEYS}
      AI_GUARDIAN_DB_PATH: /app/data/ai_guardian.db
      AI_GUARDIAN_RATE_LIMIT_PER_MINUTE: 120
    volumes:
      - ai_guardian_data:/app/data

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - ai-guardian

volumes:
  ai_guardian_data:
  caddy_data:
  caddy_config:
```

```bash
# Run with Caddy
docker compose -f docker-compose.with-caddy.yml up --build -d
```

---

## Production Checklist

Before going live:

- [ ] TLS certificate installed and auto-renewing
- [ ] `ssl_protocols` restricted to TLSv1.2+
- [ ] HSTS header enabled
- [ ] AI_GUARDIAN_BOOTSTRAP_KEYS set to long random value
- [ ] Dashboard password set (if web UI exposed)
- [ ] Rate limit configured appropriately
- [ ] Backup procedure established
- [ ] Monitoring/alerting on `/health` endpoint
