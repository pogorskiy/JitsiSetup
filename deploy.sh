#!/bin/bash
#
# Jitsi Meet + Google Auth Deployment Script
# Deploys Jitsi Meet with Google OAuth2 authentication for moderators
#
# Usage: ./deploy.sh --domain <domain> --google-client-id <id> --google-client-secret <secret> --allowed-domains <domains> [--timezone <tz>]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
TIMEZONE="UTC"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JITSI_DIR="/opt/docker-jitsi-meet"
AUTH_SERVICE_DIR="/opt/jitsi-auth"

# ============================================================================
# Logging Functions
# ============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================================================
# 8.1 Argument Parsing and Validation
# ============================================================================

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Required Options:
    --domain <domain>              Main Jitsi domain (e.g., meet.example.com)
    --google-client-id <id>        Google OAuth2 Client ID
    --google-client-secret <secret> Google OAuth2 Client Secret
    --allowed-domains <domains>    Comma-separated list of allowed email domains

Optional:
    --timezone <tz>                Server timezone (default: UTC)
    --help                         Show this help message

Example:
    $0 --domain meet.example.com \\
       --google-client-id "123456.apps.googleusercontent.com" \\
       --google-client-secret "GOCSPX-xxxxx" \\
       --allowed-domains "example.com,company.org" \\
       --timezone "Europe/Moscow"
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                MAIN_DOMAIN="$2"
                shift 2
                ;;
            --google-client-id)
                GOOGLE_CLIENT_ID="$2"
                shift 2
                ;;
            --google-client-secret)
                GOOGLE_CLIENT_SECRET="$2"
                shift 2
                ;;
            --allowed-domains)
                ALLOWED_DOMAINS="$2"
                shift 2
                ;;
            --timezone)
                TIMEZONE="$2"
                shift 2
                ;;
            --help)
                print_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

validate_arguments() {
    local missing=0

    if [[ -z "$MAIN_DOMAIN" ]]; then
        log_error "Missing required parameter: --domain"
        missing=1
    fi

    if [[ -z "$GOOGLE_CLIENT_ID" ]]; then
        log_error "Missing required parameter: --google-client-id"
        missing=1
    fi

    if [[ -z "$GOOGLE_CLIENT_SECRET" ]]; then
        log_error "Missing required parameter: --google-client-secret"
        missing=1
    fi

    if [[ -z "$ALLOWED_DOMAINS" ]]; then
        log_error "Missing required parameter: --allowed-domains"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        echo ""
        print_usage
        exit 1
    fi

    log_info "Configuration validated successfully"
    log_info "  Main Domain: $MAIN_DOMAIN"
    log_info "  Auth Domain: $(derive_auth_domain "$MAIN_DOMAIN")"
    log_info "  Timezone: $TIMEZONE"
    log_info "  Allowed Domains: $ALLOWED_DOMAINS"
}


# ============================================================================
# 8.2 Domain Derivation Function
# ============================================================================

# Derives auth subdomain from main domain
# Example: meet.example.com -> auth.meet.example.com
derive_auth_domain() {
    local main_domain="$1"
    echo "auth.${main_domain}"
}


# ============================================================================
# 8.4 Template Substitution Function
# ============================================================================

# Generate random secret for JWT and state signing
generate_secret() {
    openssl rand -hex 32
}

# Substitute placeholders in a template file
# Usage: substitute_template <template_file> <output_file>
substitute_template() {
    local template_file="$1"
    local output_file="$2"

    if [[ ! -f "$template_file" ]]; then
        log_error "Template file not found: $template_file"
        return 1
    fi

    # Perform substitutions
    sed -e "s|\${MAIN_DOMAIN}|${MAIN_DOMAIN}|g" \
        -e "s|\${AUTH_DOMAIN}|${AUTH_DOMAIN}|g" \
        -e "s|\${TIMEZONE}|${TIMEZONE}|g" \
        -e "s|\${GOOGLE_CLIENT_ID}|${GOOGLE_CLIENT_ID}|g" \
        -e "s|\${GOOGLE_CLIENT_SECRET}|${GOOGLE_CLIENT_SECRET}|g" \
        -e "s|\${ALLOWED_DOMAINS}|${ALLOWED_DOMAINS}|g" \
        -e "s|\${APP_ID}|${APP_ID}|g" \
        -e "s|\${APP_SECRET}|${APP_SECRET}|g" \
        -e "s|\${STATE_SECRET}|${STATE_SECRET}|g" \
        "$template_file" > "$output_file"

    log_info "Generated: $output_file"
}


# ============================================================================
# 8.6 Dependency Installation Function
# ============================================================================

install_dependencies() {
    log_info "Installing system dependencies..."

    # Update package lists
    apt-get update

    # Install Docker
    if ! command -v docker &> /dev/null; then
        log_info "Installing Docker..."
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        systemctl enable docker
        systemctl start docker
    else
        log_info "Docker already installed"
    fi

    # Install nginx
    if ! command -v nginx &> /dev/null; then
        log_info "Installing nginx..."
        apt-get install -y nginx
        systemctl enable nginx
    else
        log_info "nginx already installed"
    fi

    # Install certbot
    if ! command -v certbot &> /dev/null; then
        log_info "Installing certbot..."
        apt-get install -y certbot python3-certbot-nginx
    else
        log_info "certbot already installed"
    fi

    # Install Python venv
    log_info "Installing Python dependencies..."
    apt-get install -y python3-venv python3-pip

    # Configure UFW firewall
    log_info "Configuring firewall..."
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp    # SSH
        ufw allow 80/tcp    # HTTP
        ufw allow 443/tcp   # HTTPS
        ufw allow 10000/udp # Jitsi JVB
        ufw --force enable
    else
        log_warn "UFW not found, skipping firewall configuration"
    fi

    log_info "Dependencies installed successfully"
}


# ============================================================================
# 8.7 Jitsi Setup Function
# ============================================================================

setup_jitsi() {
    log_info "Setting up Jitsi Meet..."

    # Clone docker-jitsi-meet if not exists
    if [[ ! -d "$JITSI_DIR" ]]; then
        log_info "Cloning docker-jitsi-meet..."
        git clone https://github.com/jitsi/docker-jitsi-meet.git "$JITSI_DIR"
    else
        log_info "docker-jitsi-meet already exists, updating..."
        cd "$JITSI_DIR"
        git pull
    fi

    cd "$JITSI_DIR"

    # Create required directories
    mkdir -p ~/.jitsi-meet-cfg/{web,transcripts,prosody/config,prosody/prosody-plugins-custom,jicofo,jvb,jigasi,jibri}

    # Copy example .env and generate passwords FIRST
    log_info "Copying example .env and generating passwords..."
    if [[ -f "./env.example" ]]; then
        cp ./env.example ./.env
    fi
    
    # Run gen-passwords.sh to generate secure passwords
    log_info "Generating Jitsi passwords..."
    if [[ -f "./gen-passwords.sh" ]]; then
        chmod +x ./gen-passwords.sh
        ./gen-passwords.sh
    fi

    # Append our custom settings to .env (don't overwrite passwords!)
    log_info "Appending custom Jitsi settings..."
    cat >> "${JITSI_DIR}/.env" << EOF

# ============================================
# Custom settings added by deploy script
# ============================================

# Timezone
TZ=${TIMEZONE}

# Disable internal HTTPS (nginx handles SSL)
DISABLE_HTTPS=1
ENABLE_LETSENCRYPT=0

# HTTP ports (internal, behind nginx)
HTTP_PORT=8000
HTTPS_PORT=8443

# Public URL
PUBLIC_URL=https://${MAIN_DOMAIN}

# JWT Authentication
ENABLE_AUTH=1
AUTH_TYPE=jwt
ENABLE_GUESTS=1
JWT_APP_ID=${APP_ID}
JWT_APP_SECRET=${APP_SECRET}

# Token Auth URL - redirects to Auth Service
TOKEN_AUTH_URL=https://${AUTH_DOMAIN}/auth/{room}

# Config directory
CONFIG=~/.jitsi-meet-cfg
EOF

    # Start Jitsi containers
    log_info "Starting Jitsi containers..."
    docker compose up -d

    log_info "Jitsi Meet setup complete"
}


# ============================================================================
# 8.8 Auth Service Setup Function
# ============================================================================

setup_auth_service() {
    log_info "Setting up Auth Service..."

    # Create auth service directory
    mkdir -p "$AUTH_SERVICE_DIR"

    # Copy auth service files
    log_info "Copying Auth Service files..."
    cp "${SCRIPT_DIR}/auth-service/app.py" "$AUTH_SERVICE_DIR/"
    cp "${SCRIPT_DIR}/auth-service/utils.py" "$AUTH_SERVICE_DIR/"
    cp "${SCRIPT_DIR}/auth-service/requirements.txt" "$AUTH_SERVICE_DIR/"

    # Create Python virtual environment
    log_info "Creating Python virtual environment..."
    python3 -m venv "${AUTH_SERVICE_DIR}/venv"

    # Install Python dependencies
    log_info "Installing Python dependencies..."
    "${AUTH_SERVICE_DIR}/venv/bin/pip" install --upgrade pip
    "${AUTH_SERVICE_DIR}/venv/bin/pip" install -r "${AUTH_SERVICE_DIR}/requirements.txt"

    # Generate .env file
    log_info "Generating Auth Service .env file..."
    substitute_template "${SCRIPT_DIR}/deploy/templates/auth-service.env.template" "${AUTH_SERVICE_DIR}/.env"

    # Create systemd unit file
    log_info "Creating systemd unit file..."
    cp "${SCRIPT_DIR}/deploy/templates/jitsi-auth.service.template" "/etc/systemd/system/jitsi-auth.service"

    # Set correct ownership
    chown -R www-data:www-data "$AUTH_SERVICE_DIR"

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable jitsi-auth
    systemctl start jitsi-auth

    log_info "Auth Service setup complete"
}


# ============================================================================
# 8.9 Nginx Setup Function
# ============================================================================

setup_nginx() {
    log_info "Setting up nginx..."

    # Remove default site if exists
    rm -f /etc/nginx/sites-enabled/default

    # Generate nginx config for Jitsi
    log_info "Generating nginx config for Jitsi..."
    substitute_template "${SCRIPT_DIR}/deploy/templates/nginx-jitsi.conf.template" "/etc/nginx/sites-available/jitsi"

    # Generate nginx config for Auth Service
    log_info "Generating nginx config for Auth Service..."
    substitute_template "${SCRIPT_DIR}/deploy/templates/nginx-auth.conf.template" "/etc/nginx/sites-available/auth"

    # Enable sites
    ln -sf /etc/nginx/sites-available/jitsi /etc/nginx/sites-enabled/jitsi
    ln -sf /etc/nginx/sites-available/auth /etc/nginx/sites-enabled/auth

    # Test nginx configuration (will fail until SSL certs are obtained)
    # We'll create temporary self-signed certs first
    log_info "Creating temporary SSL certificates for nginx test..."
    mkdir -p "/etc/letsencrypt/live/${MAIN_DOMAIN}"
    mkdir -p "/etc/letsencrypt/live/${AUTH_DOMAIN}"

    # Create temporary self-signed certs if Let's Encrypt certs don't exist
    if [[ ! -f "/etc/letsencrypt/live/${MAIN_DOMAIN}/fullchain.pem" ]]; then
        openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
            -keyout "/etc/letsencrypt/live/${MAIN_DOMAIN}/privkey.pem" \
            -out "/etc/letsencrypt/live/${MAIN_DOMAIN}/fullchain.pem" \
            -subj "/CN=${MAIN_DOMAIN}"
    fi

    if [[ ! -f "/etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem" ]]; then
        openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
            -keyout "/etc/letsencrypt/live/${AUTH_DOMAIN}/privkey.pem" \
            -out "/etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem" \
            -subj "/CN=${AUTH_DOMAIN}"
    fi

    # Create SSL options file if not exists
    if [[ ! -f "/etc/letsencrypt/options-ssl-nginx.conf" ]]; then
        cat > /etc/letsencrypt/options-ssl-nginx.conf << 'EOF'
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
EOF
    fi

    # Create DH params if not exists
    if [[ ! -f "/etc/letsencrypt/ssl-dhparams.pem" ]]; then
        log_info "Generating DH parameters (this may take a while)..."
        openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048
    fi

    # Test nginx configuration
    log_info "Testing nginx configuration..."
    nginx -t

    # Reload nginx
    systemctl reload nginx

    log_info "nginx setup complete"
}


# ============================================================================
# 8.10 SSL Setup Function
# ============================================================================

setup_ssl() {
    log_info "Setting up SSL certificates..."

    # Stop nginx to free port 80 for standalone mode
    log_info "Stopping nginx for certificate acquisition..."
    systemctl stop nginx

    # Remove temporary self-signed certificates
    rm -f "/etc/letsencrypt/live/${MAIN_DOMAIN}/fullchain.pem"
    rm -f "/etc/letsencrypt/live/${MAIN_DOMAIN}/privkey.pem"
    rm -f "/etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem"
    rm -f "/etc/letsencrypt/live/${AUTH_DOMAIN}/privkey.pem"

    # Obtain SSL certificate for main domain using standalone mode
    log_info "Obtaining SSL certificate for ${MAIN_DOMAIN}..."
    certbot certonly --standalone -d "${MAIN_DOMAIN}" --non-interactive --agree-tos --email "admin@${MAIN_DOMAIN}"

    # Obtain SSL certificate for auth domain using standalone mode
    log_info "Obtaining SSL certificate for ${AUTH_DOMAIN}..."
    certbot certonly --standalone -d "${AUTH_DOMAIN}" --non-interactive --agree-tos --email "admin@${MAIN_DOMAIN}"

    # Start nginx with real certificates
    log_info "Starting nginx with Let's Encrypt certificates..."
    systemctl start nginx

    # Set up automatic renewal with nginx reload hook
    log_info "Configuring certbot auto-renewal..."
    systemctl enable certbot.timer
    systemctl start certbot.timer

    # Create renewal hook to reload nginx after certificate renewal
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh << 'EOF'
#!/bin/bash
systemctl reload nginx
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

    # Test renewal
    certbot renew --dry-run

    log_info "SSL setup complete"
}


# ============================================================================
# 8.11 Main Deploy Orchestration
# ============================================================================

main() {
    log_info "=========================================="
    log_info "Jitsi Meet + Google Auth Deployment"
    log_info "=========================================="

    # Parse command line arguments
    parse_arguments "$@"

    # Derive auth domain from main domain
    AUTH_DOMAIN=$(derive_auth_domain "$MAIN_DOMAIN")

    # Validate all required arguments
    validate_arguments

    # Generate secrets for JWT and state signing
    log_info "Generating security secrets..."
    APP_ID="jitsi"
    APP_SECRET=$(generate_secret)
    STATE_SECRET=$(generate_secret)

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi

    # Execute deployment steps
    log_info ""
    log_info "Step 1/5: Installing dependencies..."
    install_dependencies

    log_info ""
    log_info "Step 2/5: Setting up Jitsi Meet..."
    setup_jitsi

    log_info ""
    log_info "Step 3/5: Setting up Auth Service..."
    setup_auth_service

    log_info ""
    log_info "Step 4/5: Setting up nginx..."
    setup_nginx

    log_info ""
    log_info "Step 5/5: Setting up SSL certificates..."
    setup_ssl

    # Final status
    log_info ""
    log_info "=========================================="
    log_info "Deployment Complete!"
    log_info "=========================================="
    log_info ""
    log_info "Jitsi Meet: https://${MAIN_DOMAIN}"
    log_info "Auth Service: https://${AUTH_DOMAIN}"
    log_info ""
    log_info "To join a room as moderator:"
    log_info "  1. Go to https://${MAIN_DOMAIN}/roomname"
    log_info "  2. Click 'I am the host'"
    log_info "  3. Login with Google (allowed domains: ${ALLOWED_DOMAINS})"
    log_info ""
    log_info "Service management:"
    log_info "  - Jitsi: cd ${JITSI_DIR} && docker compose [up -d|down|logs]"
    log_info "  - Auth: systemctl [start|stop|restart|status] jitsi-auth"
    log_info "  - nginx: systemctl [reload|restart|status] nginx"
    log_info ""
}

# Run main function with all arguments
main "$@"
