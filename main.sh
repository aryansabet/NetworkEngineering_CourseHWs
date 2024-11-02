#!/bin/bash

# Exit on any error
set -e

# Configuration
DOMAIN=""
EMAIL=""
NODE_PORT="3000"
PROJECT_DIR="/var/www/secure-website"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${2:-$NC}$1${NC}"
}

error() {
    log "$1" "$RED"
    exit 1
}

# Validate inputs
validate_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]] || error "Invalid domain format"
}

validate_email() {
    [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || error "Invalid email format"
}

get_inputs() {
    read -p "Enter domain name (without www): " DOMAIN
    validate_domain "$DOMAIN"
    read -p "Enter email address: " EMAIL
    validate_email "$EMAIL"
}

install_dependencies() {
    log "Installing dependencies..." "$YELLOW"
    apt-get update
    apt-get install -y curl nginx certbot python3-certbot-nginx ufw

    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs

    log "Node.js $(node -v) installed" "$GREEN"
}

setup_firewall() {
    log "Configuring firewall..." "$YELLOW"
    ufw allow 'Nginx Full'
    ufw allow OpenSSH
    ufw allow "$NODE_PORT"/tcp
    ufw --force enable
}

write_nginx_config() {
    local config_path="/etc/nginx/sites-available/$DOMAIN"

    # Initial HTTP config
    echo "server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}" >"$config_path"

    ln -sf "$config_path" /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl restart nginx
}

setup_ssl() {
    log "Setting up SSL with Let's Encrypt..." "$YELLOW"
    certbot --nginx \
        -d "$DOMAIN" \
        -d "www.$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --redirect

    systemctl enable certbot.timer
    systemctl start certbot.timer
}

write_nginx_ssl_config() {
    local config_path="/etc/nginx/sites-available/$DOMAIN"

    echo "server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    location / {
        proxy_pass http://localhost:$NODE_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}" >"$config_path"

    nginx -t && systemctl restart nginx
}

setup_nodejs_app() {
    log "Setting up Node.js application..." "$YELLOW"

    # Create project directory
    mkdir -p "$PROJECT_DIR"
    chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_DIR"

    # Create package.json
    echo '{
  "name": "secure-website",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "helmet": "^7.1.0"
  }
}' >"$PROJECT_DIR/package.json"

    # Create app.js
    echo "import express from 'express';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || $NODE_PORT;

app.use(helmet());
app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(\`Server running on port \${PORT}\`);
});" >"$PROJECT_DIR/app.js"

    # Create public directory and index.html
    mkdir -p "$PROJECT_DIR/public"
    echo "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Secure Website</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
        }
        .status {
            color: #4CAF50;
            padding: 10px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>Welcome to my secure website!</h1>
    <div class=\"status\">
        <p>✅ This site is protected by HTTPS using Let's Encrypt</p>
        <p>🚀 Running on Node.js $(node -v)</p>
    </div>
</body>
</html>" >"$PROJECT_DIR/public/index.html"

    # Install dependencies
    cd "$PROJECT_DIR"
    sudo -u "$SUDO_USER" npm install
}

create_service() {
    log "Creating systemd service..." "$YELLOW"

    echo "[Unit]
Description=Secure Website Node.js Application
After=network.target

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/secure-website.service

    systemctl enable secure-website
    systemctl start secure-website
}

main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo)"
    fi

    log "Starting secure website setup..." "$GREEN"

    get_inputs
    install_dependencies
    setup_firewall
    write_nginx_config
    setup_ssl
    write_nginx_ssl_config
    setup_nodejs_app
    create_service

    log "Installation completed successfully!" "$GREEN"
    log "Your secure website is now available at https://$DOMAIN" "$GREEN"
    log "Node.js version: $(node -v)" "$GREEN"
}

main "$@"
