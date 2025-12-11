#!/bin/bash
################################################################################
# Caldera + Nginx Automatic Deployment Script
# For Merlino Excel Add-in Integration
#
# Version: 1.3.0
# Last Updated: 2025-12-11
#
# SMART MODE:
#   - Fresh install: Installs everything (Caldera + Nginx + auto-start)
#   - Existing install: Checks/starts Nginx and Caldera
#   - Always: Configures systemd for auto-start on boot
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/x3m-ai/caldera/master/start-caldera.sh | sudo bash
#   OR
#   wget -qO- https://raw.githubusercontent.com/x3m-ai/caldera/master/start-caldera.sh | sudo bash
#   OR
#   sudo bash start-caldera.sh --ip 192.168.1.100
################################################################################

# Colors - defined BEFORE verbose mode to avoid showing escape sequences
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Enable verbose and error modes AFTER setting up colors
set -e  # Exit on error
set -x  # Print commands (verbose debug mode for sysadmin)

# Script version
SCRIPT_VERSION="1.3.0"

# Detect if this is a fresh install or existing installation
EXISTING_INSTALL=false

# Default configuration
# Auto-detect current user if Caldera already exists
if [ -d "/home/morgana/caldera" ]; then
    DETECTED_USER=$(stat -c '%U' /home/morgana/caldera 2>/dev/null || echo "morgana")
    CALDERA_USER="${CALDERA_USER:-$DETECTED_USER}"
    CALDERA_DIR="${CALDERA_DIR:-/home/morgana/caldera}"
else
    CALDERA_USER="${CALDERA_USER:-caldera}"
    CALDERA_DIR="${CALDERA_DIR:-/opt/caldera}"
fi

CALDERA_PORT="8888"
NGINX_PORT="443"
SERVER_IP=""
AUTO_DETECT_IP=true
BRANCH="master"
TEST_MODE=false

################################################################################
# Functions
################################################################################

print_banner() {
    { set +x; } 2>/dev/null
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║        CALDERA + NGINX AUTOMATIC DEPLOYMENT                 ║"
    echo "║        For Merlino Excel Add-in Integration                 ║"
    echo "║                                                              ║"
    echo "║        Version: ${SCRIPT_VERSION}                                  ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    set -x
}

log_info() {
    { set +x; } 2>/dev/null
    echo -e "${CYAN}[INFO]${NC} $1"
    set -x
}

log_success() {
    { set +x; } 2>/dev/null
    echo -e "${GREEN}[✓]${NC} $1"
    set -x
}

log_warning() {
    { set +x; } 2>/dev/null
    echo -e "${YELLOW}[⚠]${NC} $1"
    set -x
}

log_error() {
    { set +x; } 2>/dev/null
    echo -e "${RED}[✗]${NC} $1"
    set -x
}

log_step() {
    { set +x; } 2>/dev/null
    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}▶ $1${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    set -x
}

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_apt_lock() {
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        log_warning "APT is locked by another process. Waiting..."
        local i=0
        while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
            sleep 1
            i=$((i + 1))
            if [ $i -gt 60 ]; then
                log_error "APT still locked after 60 seconds. Please kill other apt processes and retry."
                exit 1
            fi
        done
        log_info "APT lock released, continuing..."
    fi
}

detect_ip() {
    if [ "$AUTO_DETECT_IP" = true ]; then
        # Try to detect primary IP
        SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
        if [ -z "$SERVER_IP" ]; then
            SERVER_IP="127.0.0.1"
            log_warning "Could not detect IP, using 127.0.0.1"
        else
            log_info "Detected server IP: ${GREEN}$SERVER_IP${NC}"
        fi
    fi
}

check_existing_installation() {
    if [ -d "$CALDERA_DIR" ] && [ -f "$CALDERA_DIR/server.py" ]; then
        EXISTING_INSTALL=true
        log_info "${GREEN}Existing Caldera installation detected${NC}"
        return 0
    else
        EXISTING_INSTALL=false
        log_info "Fresh installation - will install everything"
        return 0
    fi
}

ensure_nginx_running() {
    log_info "Checking Nginx status..."
    
    if ! systemctl is-active --quiet nginx; then
        log_warning "Nginx is not running, starting it..."
        systemctl start nginx
        sleep 2
        
        if systemctl is-active --quiet nginx; then
            log_success "Nginx started successfully"
        else
            log_error "Failed to start Nginx"
            return 1
        fi
    else
        log_success "Nginx is already running"
    fi
    
    # Ensure Nginx is enabled for auto-start
    if ! systemctl is-enabled --quiet nginx; then
        log_info "Enabling Nginx auto-start on boot..."
        systemctl enable nginx
        log_success "Nginx auto-start enabled"
    fi
    
    return 0
}

ensure_caldera_running() {
    log_info "Checking Caldera status..."
    
    local service_name="caldera"
    
    if ! systemctl is-active --quiet ${service_name}; then
        log_warning "Caldera is not running, starting it..."
        systemctl start ${service_name}
        sleep 5
        
        if systemctl is-active --quiet ${service_name}; then
            log_success "Caldera started successfully"
        else
            log_error "Failed to start Caldera"
            log_info "Check logs with: journalctl -u ${service_name} -n 50"
            return 1
        fi
    else
        log_success "Caldera is already running"
    fi
    
    # Ensure Caldera is enabled for auto-start
    if ! systemctl is-enabled --quiet ${service_name}; then
        log_info "Enabling Caldera auto-start on boot..."
        systemctl enable ${service_name}
        log_success "Caldera auto-start enabled"
    fi
    
    return 0
}

install_dependencies() {
    log_step "STEP 1: Installing System Dependencies"
    log_info "Installing system dependencies (this may take a few minutes)..."
    echo ""
    
    check_apt_lock
    
    export DEBIAN_FRONTEND=noninteractive
    
    log_info "Updating package lists..."
    if ! apt-get update; then
        log_error "Failed to update package lists"
        return 1
    fi
    
    log_info "Installing packages: Python3, Nginx, Git, OpenSSL, UFW..."
    echo "   This step may take 2-5 minutes depending on your connection..."
    if ! apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        nginx \
        openssl \
        git \
        curl \
        ufw \
        net-tools; then
        log_error "Failed to install system packages"
        return 1
    fi
    
    echo ""
    log_success "System dependencies installed"
}

create_caldera_user() {
    if id "$CALDERA_USER" &>/dev/null; then
        log_info "User $CALDERA_USER already exists"
    else
        log_info "Creating user: $CALDERA_USER"
        useradd -r -m -s /bin/bash "$CALDERA_USER"
        log_success "User $CALDERA_USER created"
    fi
}

clone_or_update_caldera() {
    log_step "STEP 2: Cloning/Updating Caldera Repository"
    if [ -d "$CALDERA_DIR" ]; then
        log_info "Caldera directory exists, updating..."
        cd "$CALDERA_DIR"
        sudo -u "$CALDERA_USER" git pull origin "$BRANCH" || true
        log_info "Updating submodules (plugins)..."
        sudo -u "$CALDERA_USER" git submodule update --init --recursive || true
    else
        log_info "Cloning Caldera repository with all plugins..."
        echo ""
        git clone --recursive --progress https://github.com/x3m-ai/caldera.git "$CALDERA_DIR"
        chown -R "$CALDERA_USER":"$CALDERA_USER" "$CALDERA_DIR"
    fi
    echo ""
    log_success "Caldera repository ready"
}

setup_python_environment() {
    log_step "STEP 3: Setting Up Python Environment"
    log_info "Setting up Python virtual environment..."
    
    cd "$CALDERA_DIR"
    
    if [ ! -d "venv" ]; then
        sudo -u "$CALDERA_USER" python3 -m venv venv
        log_success "Virtual environment created"
    fi
    
    log_info "Installing Python dependencies (this may take 3-5 minutes)..."
    echo ""
    sudo -u "$CALDERA_USER" bash -c "source venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt"
    
    echo ""
    log_success "Python environment configured"
}

setup_nodejs_and_build_frontend() {
    log_step "STEP 3.5: Setting Up Node.js and Building Frontend"
    
    # Check if Node.js is installed
    if ! command -v node &> /dev/null; then
        log_info "Node.js not found, installing..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
        log_success "Node.js installed: $(node --version)"
    else
        log_info "Node.js already installed: $(node --version)"
    fi
    
    # Build Magma plugin frontend
    if [ -d "$CALDERA_DIR/plugins/magma" ]; then
        log_info "Building Magma plugin frontend (this may take 2-3 minutes)..."
        cd "$CALDERA_DIR/plugins/magma"
        
        # Check if dist/assets exists
        if [ ! -d "dist/assets" ]; then
            log_info "Installing npm dependencies..."
            sudo -u "$CALDERA_USER" npm install --legacy-peer-deps
            
            log_info "Building Vue.js frontend..."
            sudo -u "$CALDERA_USER" npm run build
            
            if [ -d "dist/assets" ]; then
                log_success "Frontend built successfully"
            else
                log_error "Frontend build failed - dist/assets not created"
                return 1
            fi
        else
            log_info "Frontend already built (dist/assets exists)"
        fi
    else
        log_warning "Magma plugin not found, skipping frontend build"
    fi
}

setup_nginx() {
    log_step "STEP 4: Generating SSL Certificate and Configuring Nginx"
    log_info "Configuring Nginx reverse proxy..."
    
    # Create SSL directory
    mkdir -p /etc/nginx/ssl
    chmod 755 /etc/nginx/ssl
    
    # Generate SSL certificate if not exists
    if [ ! -f "/etc/nginx/ssl/caldera.crt" ]; then
        log_info "Generating 4096-bit RSA SSL certificate (valid for 10 years)..."
        openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
            -keyout /etc/nginx/ssl/caldera.key \
            -out /etc/nginx/ssl/caldera.crt \
            -subj "/C=IT/ST=State/L=City/O=X3M-AI/OU=Merlino/CN=$SERVER_IP" \
            -addext "subjectAltName=IP:$SERVER_IP"
        
        chmod 644 /etc/nginx/ssl/caldera.crt
        chmod 600 /etc/nginx/ssl/caldera.key
        log_success "SSL certificate generated: /etc/nginx/ssl/caldera.crt"
    else
        log_info "SSL certificate already exists at /etc/nginx/ssl/caldera.crt"
    fi
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/caldera-proxy << EOF
# Nginx Reverse Proxy Configuration for Caldera + CORS
# Auto-generated by deploy script

server {
    listen $NGINX_PORT ssl http2;
    listen [::]:$NGINX_PORT ssl http2;
    server_name $SERVER_IP;
    
    ssl_certificate /etc/nginx/ssl/caldera.crt;
    ssl_certificate_key /etc/nginx/ssl/caldera.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    location / {
        # CORS Headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS, PATCH' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, KEY, Authorization, X-Requested-With, Accept, Origin' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length, Content-Type' always;
        add_header 'Access-Control-Max-Age' '86400' always;
        add_header 'Access-Control-Allow-Credentials' 'true' always;
        
        # Handle preflight OPTIONS requests
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS, PATCH' always;
            add_header 'Access-Control-Allow-Headers' 'Content-Type, KEY, Authorization, X-Requested-With, Accept, Origin' always;
            add_header 'Access-Control-Max-Age' '86400' always;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' '0';
            return 204;
        }
        
        # Proxy to Caldera
        proxy_pass http://127.0.0.1:$CALDERA_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        proxy_buffering off;
        proxy_cache_bypass \$http_upgrade;
        proxy_intercept_errors off;
    }
    
    location /nginx-health {
        access_log off;
        return 200 "Nginx proxy is running\n";
        add_header Content-Type text/plain;
    }
    
    access_log /var/log/nginx/caldera-access.log;
    error_log /var/log/nginx/caldera-error.log warn;
}

server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_IP;
    return 301 https://\$host\$request_uri;
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/caldera-proxy /etc/nginx/sites-enabled/caldera-proxy
    
    # Disable default site (only in production mode)
    if [ "$TEST_MODE" = false ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    
    # Test configuration
    log_info "Testing Nginx configuration..."
    nginx -t
    
    log_success "Nginx configured"
}

create_systemd_service() {
    log_step "STEP 5: Creating Systemd Auto-Start Service"
    log_info "Creating systemd service for auto-start..."
    
    local service_name="caldera"
    if [ "$TEST_MODE" = true ]; then
        service_name="caldera-test"
    fi
    
    cat > /etc/systemd/system/${service_name}.service << EOF
[Unit]
Description=Caldera C2 Framework
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=$CALDERA_USER
Group=$CALDERA_USER
WorkingDirectory=$CALDERA_DIR
Environment="PATH=$CALDERA_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$CALDERA_DIR/venv/bin/python3 $CALDERA_DIR/server.py --insecure
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=caldera

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_success "Systemd service created"
}

configure_firewall() {
    log_step "STEP 6: Configuring Firewall Rules"
    log_info "Configuring UFW firewall..."
    
    # Check if UFW is installed and active
    if command -v ufw &> /dev/null; then
        log_info "Enabling UFW..."
        ufw --force enable
        
        log_info "Opening port $NGINX_PORT (HTTPS)..."
        ufw allow $NGINX_PORT/tcp comment 'Nginx HTTPS for Caldera'
        
        log_info "Opening port 80 (HTTP redirect)..."
        ufw allow 80/tcp comment 'Nginx HTTP redirect'
        
        log_info "Ensuring SSH is allowed..."
        ufw allow ssh
        
        log_info "Current firewall status:"
        ufw status verbose
        
        log_success "Firewall configured"
    else
        log_warning "UFW not available, skipping firewall configuration"
    fi
}

start_services() {
    log_step "STEP 7: Starting and Enabling Services"
    log_info "Starting services..."
    
    local service_name="caldera"
    if [ "$TEST_MODE" = true ]; then
        service_name="caldera-test"
    fi
    
    # Start and enable Nginx
    log_info "Starting Nginx..."
    systemctl restart nginx
    log_info "Enabling Nginx auto-start..."
    systemctl enable nginx
    
    # Start and enable Caldera
    log_info "Starting Caldera..."
    systemctl restart ${service_name}
    log_info "Enabling Caldera auto-start..."
    systemctl enable ${service_name}
    
    # Wait for services to start
    sleep 3
    
    log_success "Services started"
}

build_magma_frontend() {
    log_step "Building Magma Frontend (Vue.js)"
    echo "════════════════════════════════════════════════════════════════"
    echo "▶ Building Magma Frontend (Vue.js)"
    echo "════════════════════════════════════════════════════════════════"
    
    # Check if dist already exists and is valid
    if [ -d "$CALDERA_DIR/plugins/magma/dist" ] && [ -f "$CALDERA_DIR/plugins/magma/dist/index.html" ]; then
        log_info "Frontend already built, skipping..."
        return 0
    fi
    
    log_info "Installing Node.js and npm..."
    
    # Install Node.js via NodeSource (latest LTS)
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt-get install -y nodejs
    
    log_info "Node.js version: $(node --version)"
    log_info "npm version: $(npm --version)"
    
    log_info "Building Magma frontend..."
    cd "$CALDERA_DIR/plugins/magma"
    
    # Install dependencies
    log_info "Installing npm dependencies..."
    npm install --legacy-peer-deps
    
    # Build the frontend
    log_info "Running npm build..."
    npm run build
    
    # Verify build succeeded
    if [ -d "$CALDERA_DIR/plugins/magma/dist" ] && [ -f "$CALDERA_DIR/plugins/magma/dist/index.html" ]; then
        log_success "Magma frontend built successfully"
    else
        log_error "Frontend build failed - dist directory not created"
        return 1
    fi
    
    cd "$CALDERA_DIR"
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    local errors=0
    local service_name="caldera"
    if [ "$TEST_MODE" = true ]; then
        service_name="caldera-test"
    fi
    
    # Check Nginx
    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx is not running"
        errors=$((errors + 1))
    fi
    
    # Check Caldera
    if systemctl is-active --quiet ${service_name}; then
        log_success "Caldera is running"
    else
        log_error "Caldera is not running"
        errors=$((errors + 1))
    fi
    
    # Check ports
    sleep 2
    if ss -tuln | grep -q ":$CALDERA_PORT "; then
        log_success "Caldera listening on port $CALDERA_PORT"
    else
        log_warning "Caldera port $CALDERA_PORT not detected yet (may still be starting)"
    fi
    
    if ss -tuln | grep -q ":$NGINX_PORT "; then
        log_success "Nginx listening on port $NGINX_PORT"
    else
        log_error "Nginx port $NGINX_PORT not listening"
        errors=$((errors + 1))
    fi
    
    return $errors
}

print_completion_info() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    if [ "$TEST_MODE" = true ]; then
        echo -e "${GREEN}║           TEST DEPLOYMENT COMPLETED SUCCESSFULLY!            ║${NC}"
    elif [ "$EXISTING_INSTALL" = true ]; then
        echo -e "${GREEN}║           CALDERA IS NOW RUNNING SUCCESSFULLY!               ║${NC}"
    else
        echo -e "${GREEN}║              DEPLOYMENT COMPLETED SUCCESSFULLY!              ║${NC}"
    fi
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ "$TEST_MODE" = true ]; then
        echo -e "${YELLOW}⚠️  This is a TEST installation - running alongside production${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}📍 SERVER INFORMATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "   Server IP:         ${GREEN}$SERVER_IP${NC}"
    echo -e "   Caldera Backend:   ${GREEN}http://127.0.0.1:$CALDERA_PORT${NC}"
    echo -e "   Nginx Proxy:       ${GREEN}https://$SERVER_IP:$NGINX_PORT${NC}"
    echo ""
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🔐 SSL CERTIFICATE - REQUIRED FOR MERLINO${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "   Certificate Location:"
    echo -e "   ${GREEN}/etc/nginx/ssl/caldera.crt${NC}"
    echo ""
    echo -e "   ${YELLOW}⚠️  IMPORTANT: Copy this certificate to your Windows client!${NC}"
    echo ""
    echo -e "   Step 1: Export certificate from Linux server"
    echo -e "   ${GREEN}scp root@$SERVER_IP:/etc/nginx/ssl/caldera.crt ~/Desktop/caldera.crt${NC}"
    echo ""
    echo -e "   Step 2: Install certificate on Windows"
    echo -e "   - Double-click ${GREEN}caldera.crt${NC}"
    echo -e "   - Click ${GREEN}\"Install Certificate\"${NC}"
    echo -e "   - Select ${GREEN}\"Local Machine\"${NC}"
    echo -e "   - Choose ${GREEN}\"Trusted Root Certification Authorities\"${NC}"
    echo -e "   - Complete the wizard"
    echo ""
    echo -e "   Step 3: Restart Excel after certificate installation"
    echo ""
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🪟 MERLINO EXCEL ADD-IN CONFIGURATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "   Caldera URL:       ${GREEN}https://$SERVER_IP${NC}"
    echo -e "   Port:              ${GREEN}443${NC} (HTTPS)"
    echo -e "   API Key:           ${GREEN}ADMIN123${NC} (check conf/default.yml for your key)"
    echo ""
    echo -e "   Test connection from Windows:"
    echo -e "   ${GREEN}Invoke-WebRequest -Uri \"https://$SERVER_IP/nginx-health\" -SkipCertificateCheck${NC}"
    echo ""
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🔄 AUTO-START CONFIGURATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "   ✓ Nginx will start automatically on system boot"
    echo -e "   ✓ Caldera will start automatically on system boot"
    echo -e "   ✓ Caldera depends on Nginx (starts in correct order)"
    echo ""
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🚀 SERVICE MANAGEMENT COMMANDS${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "   Check status:      ${GREEN}systemctl status caldera nginx${NC}"
    echo -e "   Restart Caldera:   ${GREEN}systemctl restart caldera${NC}"
    echo -e "   Restart Nginx:     ${GREEN}systemctl restart nginx${NC}"
    echo -e "   View logs:         ${GREEN}journalctl -u caldera -f${NC}"
    echo -e "   Nginx logs:        ${GREEN}tail -f /var/log/nginx/caldera-access.log${NC}"
    echo ""
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🧪 TESTING ENDPOINTS${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "   Nginx health:      ${GREEN}curl -k https://$SERVER_IP/nginx-health${NC}"
    echo -e "   Caldera API:       ${GREEN}curl -k https://$SERVER_IP/api/v2/agents -H 'KEY: ADMIN123'${NC}"
    echo -e "   List abilities:    ${GREEN}curl -k https://$SERVER_IP/api/v2/abilities -H 'KEY: ADMIN123'${NC}"
    echo ""
    
    if [ "$TEST_MODE" = true ]; then
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}🧹 CLEANUP TEST INSTALLATION${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "   ${YELLOW}sudo systemctl stop caldera-test${NC}"
        echo -e "   ${YELLOW}sudo systemctl disable caldera-test${NC}"
        echo -e "   ${YELLOW}sudo rm -rf $CALDERA_DIR${NC}"
        echo -e "   ${YELLOW}sudo rm /etc/systemd/system/caldera-test.service${NC}"
        echo -e "   ${YELLOW}sudo rm /etc/nginx/sites-enabled/caldera-proxy${NC}"
        echo -e "   ${YELLOW}sudo userdel -r $CALDERA_USER${NC}"
        echo -e "   ${YELLOW}sudo systemctl daemon-reload && sudo systemctl restart nginx${NC}"
        echo ""
    fi
    
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  🎉 Ready to use with Merlino Excel Add-in!                 ║${NC}"
    echo -e "${GREEN}║  📝 Don't forget to install the SSL certificate on Windows! ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

################################################################################
# Main Execution
################################################################################

main() {
    print_banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ip)
                SERVER_IP="$2"
                AUTO_DETECT_IP=false
                shift 2
                ;;
            --user)
                CALDERA_USER="$2"
                shift 2
                ;;
            --dir)
                CALDERA_DIR="$2"
                shift 2
                ;;
            --branch)
                BRANCH="$2"
                shift 2
                ;;
            --test)
                TEST_MODE=true
                CALDERA_USER="caldera-test"
                CALDERA_DIR="/opt/caldera-test"
                CALDERA_PORT="8889"
                NGINX_PORT="8443"
                log_info "${YELLOW}TEST MODE ENABLED${NC}"
                log_info "Using test configuration to avoid conflicts with existing installation"
                shift
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    check_root
    check_apt_lock
    detect_ip
    
    # Check if this is an existing installation
    check_existing_installation
    
    echo ""
    log_info "Starting deployment with:"
    log_info "  Server IP:      $SERVER_IP"
    log_info "  Caldera User:   $CALDERA_USER"
    log_info "  Install Dir:    $CALDERA_DIR"
    log_info "  Git Branch:     $BRANCH"
    log_info "  Mode:           $([ "$EXISTING_INSTALL" = true ] && echo "Update/Start existing" || echo "Fresh installation")"
    echo ""
    
    if [ "$EXISTING_INSTALL" = true ]; then
        # Existing installation - just check and start services
        log_info "${GREEN}Working with existing Caldera installation${NC}"
        
        # Ensure systemd service exists
        if [ ! -f "/etc/systemd/system/caldera.service" ]; then
            log_info "Systemd service not found, creating it..."
            create_systemd_service
        fi
        
        # Check if frontend is built, if not build it
        if [ ! -d "$CALDERA_DIR/plugins/magma/dist/assets" ]; then
            log_warning "Frontend not built, building now..."
            setup_nodejs_and_build_frontend
        fi
        
        # Check and start services
        ensure_nginx_running
        ensure_caldera_running
        
        # Verify everything is working
        if verify_deployment; then
            print_completion_info
            exit 0
        else
            log_error "Service startup completed with errors. Check logs for details."
            echo ""
            echo "Debug commands:"
            echo "  systemctl status caldera"
            echo "  systemctl status nginx"
            echo "  journalctl -u caldera -n 50"
            exit 1
        fi
    else
        # Fresh installation - install everything
        log_info "${GREEN}Performing fresh installation${NC}"
        
        install_dependencies
        create_caldera_user
        clone_or_update_caldera
        setup_python_environment
        setup_nodejs_and_build_frontend
        setup_nginx
        create_systemd_service
        configure_firewall
        start_services
        
        if verify_deployment; then
            print_completion_info
            exit 0
        else
            log_error "Deployment completed with errors. Check logs for details."
            echo ""
            echo "Debug commands:"
            echo "  systemctl status caldera"
            echo "  systemctl status nginx"
            echo "  journalctl -u caldera -n 50"
            exit 1
        fi
    fi
}

# Run main function
main "$@"
