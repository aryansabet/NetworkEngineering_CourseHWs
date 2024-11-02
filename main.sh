#!/bin/bash

# Configuration variables
DOMAIN=""
EMAIL=""
PROJECT_DIR="/var/www/secure-website"
APP_PORT=3000  # Changed from 443 to avoid conflict with HTTPS

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

# Install Node.js 22 and other dependencies
install_dependencies() {
    print_message "Installing dependencies..." "$YELLOW"
    sudo apt-get update
    sudo apt-get install -y curl nginx certbot python3-certbot-nginx ufw
    check_error "Failed to install basic dependencies"

    print_message "Installing Node.js..." "$YELLOW"
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs
    check_error "Failed to install Node.js"

    # Verify Node.js installation
    NODE_VERSION=$(node -v)
    print_message "Node.js version $NODE_VERSION installed successfully" "$GREEN"
}

# Configure firewall
setup_firewall() {
    print_message "Configuring firewall..." "$YELLOW"
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow OpenSSH
    sudo ufw --force enable
    check_error "Failed to configure firewall"
}

# Configure Nginx
setup_nginx() {
    print_message "Configuring Nginx..." "$YELLOW"
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/$DOMAIN << EOL
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};
    
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    location / {
        proxy_pass http://localhost:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

    # Enable site and remove default
    sudo ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Test configuration
    sudo nginx -t
    check_error "Nginx configuration test failed"
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

# Create Node.js application
create_nodejs_app() {
    print_message "Creating Node.js application..." "$YELLOW"
    
    # Create project directory
    sudo mkdir -p $PROJECT_DIR
    sudo chown -R $USER:$USER $PROJECT_DIR
    
    # Create package.json
    cat > $PROJECT_DIR/package.json << EOL
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
    cat > $PROJECT_DIR/app.js << EOL
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || ${APP_PORT};

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(\`Server running on port \${PORT}\`);
});
EOL

    # Create public directory and index.html
    mkdir -p $PROJECT_DIR/public
    cat > $PROJECT_DIR/public/index.html << EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
            color: green;
            padding: 10px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>Welcome to my secure website!</h1>
    <div class="status">
        <p>✅ This site is protected by HTTPS using Let's Encrypt</p>
        <p>🚀 Running on Node.js $(node -v)</p>
    </div>
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
    
    cat > /etc/systemd/system/secure-website.service << EOL
[Unit]
Description=Secure Website Node.js Application
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=PORT=${APP_PORT}

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
    setup_nginx
    setup_ssl
    create_nodejs_app
    create_service
    
    # Final restart of Nginx
    sudo systemctl restart nginx
    
    print_message "Installation completed successfully!" "$GREEN"
    print_message "Your secure website is now available at https://$DOMAIN" "$GREEN"
    print_message "Node.js version: $(node -v)" "$GREEN"
}

# Run the script
main