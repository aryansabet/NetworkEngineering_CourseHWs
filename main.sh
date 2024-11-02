#!/bin/bash

# Configuration variables
DOMAIN="aryansabet.com"
EMAIL="aryansitefa@gmail.com"
PROJECT_DIR="/var/www/secure-website"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print colored messages
print_message() {
    echo -e "${2}${1}${NC}"
}

# Function to check if command succeeded
check_error() {
    if [ $? -ne 0 ]; then
        print_message "Error: $1" "$RED"
        exit 1
    fi
}

# Function to validate domain name
validate_domain() {
    if [[ ! $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        print_message "Invalid domain name format" "$RED"
        exit 1
    fi
}

# Function to validate email
validate_email() {
    if [[ ! $1 =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        print_message "Invalid email format" "$RED"
        exit 1
    fi
}

# Get user input
get_user_input() {
    read -p "Enter your domain name (without www): " DOMAIN
    validate_domain "$DOMAIN"
    read -p "Enter your email address: " EMAIL
    validate_email "$EMAIL"
}

# Install dependencies
install_dependencies() {
    print_message "Installing curl if not present..." "$YELLOW"
    sudo apt-get update
    sudo apt-get install -y curl
    check_error "Failed to install curl"

    print_message "Downloading Node.js 22 setup script..." "$YELLOW"
    curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh
    check_error "Failed to download Node.js setup script"

    print_message "Running Node.js setup script..." "$YELLOW"
    sudo -E bash nodesource_setup.sh
    check_error "Failed to run Node.js setup script"

    print_message "Installing Node.js and other dependencies..." "$YELLOW"
    sudo apt-get install -y nodejs nginx certbot python3-certbot-nginx ufw
    check_error "Failed to install dependencies"

    # Verify Node.js installation
    NODE_VERSION=$(node -v)
    print_message "Node.js version $NODE_VERSION installed successfully" "$GREEN"
}

# Configure firewall
setup_firewall() {
    print_message "Configuring firewall..." "$YELLOW"

    sudo ufw allow 'Nginx Full'
    sudo ufw allow OpenSSH
    sudo ufw --force enable
    check_error "Failed to configure firewall"
}

# Configure initial Nginx without SSL
setup_initial_nginx() {
    print_message "Configuring initial Nginx setup..." "$YELLOW"

    # Create initial Nginx configuration (HTTP only)
    cat >/etc/nginx/sites-available/$DOMAIN <<EOL
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
}
EOL

    # Create letsencrypt directory
    sudo mkdir -p /var/www/letsencrypt

    # Enable site configuration
    sudo ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/

    # Remove default site if it exists
    sudo rm -f /etc/nginx/sites-enabled/default

    # Test configuration
    sudo nginx -t
    check_error "Initial Nginx configuration test failed"

    # Restart Nginx
    sudo systemctl restart nginx
    check_error "Failed to restart Nginx"
}

# Set up Let's Encrypt certificate
setup_ssl() {
    print_message "Setting up SSL certificate..." "$YELLOW"

    sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email $EMAIL
    check_error "Failed to obtain SSL certificate"

    # Set up auto-renewal
    sudo systemctl enable certbot.timer
    sudo systemctl start certbot.timer
}

# Configure final Nginx with SSL
setup_final_nginx() {
    print_message "Configuring final Nginx setup with SSL..." "$YELLOW"

    cat >/etc/nginx/sites-available/$DOMAIN <<EOL
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    
    location / {
        return 301 https://\$host\$request_uri;
    }
    
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};
    
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    location / {
        proxy_pass http://localhost:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

    sudo nginx -t
    check_error "Final Nginx configuration test failed"

    sudo systemctl restart nginx
    check_error "Failed to restart Nginx"
}

# Create Node.js application
create_nodejs_app() {
    print_message "Creating Node.js application..." "$YELLOW"

    # Create project directory
    sudo mkdir -p $PROJECT_DIR
    sudo chown -R $USER:$USER $PROJECT_DIR

    # Create package.json
    cat >$PROJECT_DIR/package.json <<EOL
{
  "name": "secure-website",
  "version": "1.0.0",
  "description": "Secure website with Let's Encrypt",
  "main": "app.js",
  "type": "module",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
EOL

    # Create app.js
    cat >$PROJECT_DIR/app.js <<EOL
import express from 'express';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const dirname = path.dirname(filename);

const app = express();
const PORT = process.env.PORT || 443;

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const sslOptions = {
    key: fs.readFileSync('/etc/letsencrypt/live/${DOMAIN}/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/${DOMAIN}/fullchain.pem')
};

https.createServer(sslOptions, app)
    .listen(PORT, () => {
        console.log(\Secure server running on port \${PORT}\);
    });
EOL

    # Create public directory and index.html
    mkdir -p $PROJECT_DIR/public
    cat >$PROJECT_DIR/public/index.html <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Website</title>
</head>
<body>
    <h1>Welcome to my secure website!</h1>
    <p>This site is protected by HTTPS using Let's Encrypt</p>
    <p>Running on Node.js $(node -v)</p>
</body>
</html>
EOL

    # Install dependencies
    cd $PROJECT_DIR
    npm install
    check_error "Failed to install Node.js dependencies"
}

# Create systemd service
create_service() {
    print_message "Creating systemd service..." "$YELLOW"

    cat >/etc/systemd/system/secure-website.service <<EOL
[Unit]
Description=Secure Website Node.js Application
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/node app.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL

    sudo systemctl enable secure-website
    sudo systemctl start secure-website
    check_error "Failed to start Node.js application service"
}

# Main installation process
main() {
    # Check if script is run as root
    if [ "$EUID" -ne 0 ]; then
        print_message "Please run as root (sudo)" "$RED"
        exit 1
    fi

    print_message "Starting secure website setup..." "$GREEN"

    get_user_input
    install_dependencies
    setup_firewall
    setup_initial_nginx
    setup_ssl
    setup_final_nginx
    create_nodejs_app
    create_service

    print_message "Installation completed successfully!" "$GREEN"
    print_message "Your secure website is now available at https://$DOMAIN" "$GREEN"
    print_message "Node.js version: $(node -v)" "$GREEN"
}

# Run the script
main
