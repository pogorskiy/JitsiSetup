# Jitsi Meet + Google Auth Deployment

Automated deployment system for Jitsi Meet with Google OAuth2 authentication for moderators. This solution deploys a complete video conferencing infrastructure with domain-based access control.

## Features

- **One-command deployment** — Deploy entire infrastructure on a fresh Ubuntu server
- **Google OAuth2 authentication** — Moderators authenticate via Google
- **Domain-based access control** — Only users from allowed email domains get moderator rights
- **Guest access** — Guests can join without authentication (wait for moderator)
- **Automatic SSL** — Let's Encrypt certificates with auto-renewal
- **Systemd integration** — Auth service runs as a managed system service

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │              nginx :443                 │
                    │  ┌─────────────┐  ┌─────────────────┐   │
Internet ──────────►│  │ meet.domain │  │ auth.meet.domain│   │
                    │  └──────┬──────┘  └────────┬────────┘   │
                    └─────────┼──────────────────┼────────────┘
                              │                  │
                    ┌─────────▼──────┐  ┌────────▼─────────┐
                    │  Jitsi Docker  │  │   Auth Service   │
                    │    :8000       │  │     :8001        │
                    └────────────────┘  └──────────────────┘
```

## Prerequisites

### Server Requirements

- **OS**: Ubuntu 20.04 LTS or newer
- **RAM**: Minimum 4GB (8GB recommended)
- **CPU**: 2+ cores
- **Disk**: 20GB+ free space
- **Network**: Public IP address

### DNS Setup

Before running the deploy script, configure DNS records pointing to your server:

| Record Type | Name | Value |
|-------------|------|-------|
| A | meet.yourdomain.com | Your server IP |
| A | auth.meet.yourdomain.com | Your server IP |

**Important**: DNS propagation may take up to 48 hours. Verify records are active before deployment:

```bash
dig +short meet.yourdomain.com
dig +short auth.meet.yourdomain.com
```

### Google OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. Select **Web application**
6. Configure:
   - **Name**: Jitsi Auth (or any name)
   - **Authorized redirect URIs**: `https://auth.meet.yourdomain.com/oauth2/callback`
7. Save the **Client ID** and **Client Secret**

## Installation

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd jitsi-google-auth-deploy

# Make deploy script executable
chmod +x deploy.sh

# Run deployment (as root)
sudo ./deploy.sh \
    --domain meet.yourdomain.com \
    --google-client-id "YOUR_CLIENT_ID.apps.googleusercontent.com" \
    --google-client-secret "YOUR_CLIENT_SECRET" \
    --allowed-domains "yourdomain.com,partner.org"
```

### Command Line Options

| Option | Required | Description |
|--------|----------|-------------|
| `--domain` | Yes | Main Jitsi domain (e.g., `meet.example.com`) |
| `--google-client-id` | Yes | Google OAuth2 Client ID |
| `--google-client-secret` | Yes | Google OAuth2 Client Secret |
| `--allowed-domains` | Yes | Comma-separated list of allowed email domains |
| `--timezone` | No | Server timezone (default: `UTC`) |
| `--help` | No | Show help message |

### Example

```bash
sudo ./deploy.sh \
    --domain meet.sigmasoft.am \
    --google-client-id "123456789.apps.googleusercontent.com" \
    --google-client-secret "GOCSPX-abcdefghijk" \
    --allowed-domains "sigmasoft.am,partner.com" \
    --timezone "Asia/Yerevan"
```

## Usage

### Joining as Moderator

1. Navigate to `https://meet.yourdomain.com/roomname`
2. Click **"I am the host"** button
3. Authenticate with your Google account
4. If your email domain is in the allowed list, you'll be redirected back with moderator privileges

### Joining as Guest

1. Navigate to `https://meet.yourdomain.com/roomname`
2. Enter your display name
3. Wait in the lobby until a moderator admits you

## Service Management

### Jitsi (Docker)

```bash
cd /opt/docker-jitsi-meet

# View status
docker compose ps

# View logs
docker compose logs -f

# Restart
docker compose restart

# Stop
docker compose down

# Start
docker compose up -d
```

### Auth Service (Systemd)

```bash
# View status
sudo systemctl status jitsi-auth

# View logs
sudo journalctl -u jitsi-auth -f

# Restart
sudo systemctl restart jitsi-auth

# Stop
sudo systemctl stop jitsi-auth

# Start
sudo systemctl start jitsi-auth
```

### Nginx

```bash
# View status
sudo systemctl status nginx

# Test configuration
sudo nginx -t

# Reload configuration
sudo systemctl reload nginx

# Restart
sudo systemctl restart nginx
```

### SSL Certificates

Certificates are automatically renewed by certbot. To manually check:

```bash
# Check certificate status
sudo certbot certificates

# Test renewal
sudo certbot renew --dry-run

# Force renewal
sudo certbot renew --force-renewal
```

## Configuration

### Allowed Domains

To modify allowed email domains after deployment, edit the Auth Service environment file:

```bash
sudo nano /opt/jitsi-auth/.env
```

Update the `ALLOWED_MOD_DOMAINS` value:

```env
ALLOWED_MOD_DOMAINS=newdomain.com,anotherdomain.org
```

Then restart the service:

```bash
sudo systemctl restart jitsi-auth
```

### Configuration Files

| File | Description |
|------|-------------|
| `/opt/docker-jitsi-meet/.env` | Jitsi configuration |
| `/opt/jitsi-auth/.env` | Auth Service configuration |
| `/etc/nginx/sites-available/jitsi` | Nginx config for Jitsi |
| `/etc/nginx/sites-available/auth` | Nginx config for Auth Service |
| `/etc/systemd/system/jitsi-auth.service` | Systemd unit file |

## Troubleshooting

### Auth Service Not Starting

```bash
# Check logs
sudo journalctl -u jitsi-auth -n 50

# Verify .env file exists
cat /opt/jitsi-auth/.env

# Check Python venv
/opt/jitsi-auth/venv/bin/python --version
```

### SSL Certificate Issues

```bash
# Check certificate status
sudo certbot certificates

# Verify DNS is pointing to server
dig +short meet.yourdomain.com

# Check nginx error log
sudo tail -f /var/log/nginx/error.log
```

### Google OAuth Errors

1. Verify redirect URI in Google Console matches exactly: `https://auth.meet.yourdomain.com/oauth2/callback`
2. Check that OAuth consent screen is configured
3. Verify Client ID and Secret are correct in `/opt/jitsi-auth/.env`

### Jitsi Connection Issues

```bash
# Check container status
cd /opt/docker-jitsi-meet && docker compose ps

# Check container logs
docker compose logs web
docker compose logs prosody

# Verify ports
sudo netstat -tlnp | grep -E '8000|10000'
```

## Security Considerations

- All traffic is encrypted via HTTPS
- OAuth state parameter is HMAC-signed to prevent CSRF attacks
- JWT tokens are signed with a randomly generated secret
- Firewall (UFW) is configured to allow only necessary ports
- Auth Service runs as `www-data` user with limited privileges

## Ports Used

| Port | Protocol | Service |
|------|----------|---------|
| 22 | TCP | SSH |
| 80 | TCP | HTTP (redirects to HTTPS) |
| 443 | TCP | HTTPS |
| 10000 | UDP | Jitsi JVB (video bridge) |

## License

MIT License
