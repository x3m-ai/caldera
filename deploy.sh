#!/bin/bash
################################################################################
# Caldera + Nginx Automatic Deployment Script
# For Merlino Excel Add-in Integration
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/x3m-ai/caldera/master/deploy.sh | sudo bash
#   OR
#   sudo bash deploy.sh --ip 192.168.1.100
################################################################################

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
CALDERA_USER="${CALDERA_USER:-caldera}"
CALDERA_DIR="/opt/caldera"
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
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║        CALDERA + NGINX AUTOMATIC DEPLOYMENT                 ║"
    echo "║        For Merlino Excel Add-in Integration                 ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_error "This script must be run as root (use sudo)"
        exit 1
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

install_dependencies() {
    log_info "Installing system dependencies..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        nginx \
        openssl \
        git \
        curl \
        ufw \
        net-tools \
        >/dev/null 2>&1
    
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
    if [ -d "$CALDERA_DIR" ]; then
        log_info "Caldera directory exists, updating..."
        cd "$CALDERA_DIR"
        sudo -u "$CALDERA_USER" git pull origin "$BRANCH" >/dev/null 2>&1 || true
        sudo -u "$CALDERA_USER" git submodule update --init --recursive >/dev/null 2>&1 || true
    else
        log_info "Cloning Caldera repository..."
        git clone --quiet --recursive https://github.com/x3m-ai/caldera.git "$CALDERA_DIR"
        chown -R "$CALDERA_USER":"$CALDERA_USER" "$CALDERA_DIR"
    fi
    log_success "Caldera repository ready"
}

setup_python_environment() {
    log_info "Setting up Python virtual environment..."
    
    cd "$CALDERA_DIR"
    
    if [ ! -d "venv" ]; then
        sudo -u "$CALDERA_USER" python3 -m venv venv
    fi
    
    log_info "Installing Python dependencies (this may take a few minutes)..."
    sudo -u "$CALDERA_USER" bash -c "source venv/bin/activate && pip install --quiet --upgrade pip && pip install --quiet -r requirements.txt"
    
    log_success "Python environment configured"
}

setup_nginx() {
    log_info "Configuring Nginx reverse proxy..."
    
    # Create SSL directory
    mkdir -p /etc/nginx/ssl
    chmod 755 /etc/nginx/ssl
    
    # Generate SSL certificate if not exists
    if [ ! -f "/etc/nginx/ssl/caldera.crt" ]; then
        log_info "Generating SSL certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -keyout /etc/nginx/ssl/caldera.key \
            -out /etc/nginx/ssl/caldera.crt \
            -subj "/C=IT/ST=State/L=City/O=X3M-AI/OU=Merlino/CN=$SERVER_IP" \
            -addext "subjectAltName=IP:$SERVER_IP" \
            >/dev/null 2>&1
        
        chmod 644 /etc/nginx/ssl/caldera.crt
        chmod 600 /etc/nginx/ssl/caldera.key
        log_success "SSL certificate generated"
    else
        log_info "SSL certificate already exists"
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
    nginx -t >/dev/null 2>&1
    
    log_success "Nginx configured"
}

create_systemd_service() {
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
    log_info "Configuring firewall..."
    
    # Check if UFW is installed and active
    if command -v ufw &> /dev/null; then
        ufw --force enable >/dev/null 2>&1
        ufw allow $NGINX_PORT/tcp comment 'Nginx HTTPS for Caldera' >/dev/null 2>&1
        ufw allow 80/tcp comment 'Nginx HTTP redirect' >/dev/null 2>&1
        ufw allow ssh >/dev/null 2>&1
        log_success "Firewall configured"
    else
        log_warning "UFW not available, skipping firewall configuration"
    fi
}

start_services() {
    log_info "Starting services..."
    
    local service_name="caldera"
    if [ "$TEST_MODE" = true ]; then
        service_name="caldera-test"
    fi
    
    # Start and enable Nginx
    systemctl restart nginx
    systemctl enable nginx >/dev/null 2>&1
    
    # Start and enable Caldera
    systemctl restart ${service_name}
    systemctl enable ${service_name} >/dev/null 2>&1
    
    # Wait for services to start
    sleep 3
    
    log_success "Services started"
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
    
    echo -e "${CYAN}📍 Server Information:${NC}"
    echo -e "   IP Address:    ${GREEN}$SERVER_IP${NC}"
    echo -e "   Caldera:       ${GREEN}http://127.0.0.1:$CALDERA_PORT${NC}"
    echo -e "   Nginx Proxy:   ${GREEN}https://$SERVER_IP:$NGINX_PORT${NC}"
    echo ""
    echo -e "${CYAN}🔐 SSL Certificate:${NC}"
    echo -e "   Location:      ${GREEN}/etc/nginx/ssl/caldera.crt${NC}"
    echo -e "   Export to Windows:"
    echo -e "   ${YELLOW}scp root@$SERVER_IP:/etc/nginx/ssl/caldera.crt ~/caldera.crt${NC}"
    echo ""
    echo -e "${CYAN}🚀 Service Management:${NC}"
    echo -e "   Status:        ${GREEN}systemctl status caldera${NC}"
    echo -e "   Restart:       ${GREEN}systemctl restart caldera${NC}"
    echo -e "   Logs:          ${GREEN}journalctl -u caldera -f${NC}"
    echo -e "   Nginx logs:    ${GREEN}tail -f /var/log/nginx/caldera-access.log${NC}"
    echo ""
    echo -e "${CYAN}🧪 Testing:${NC}"
    echo -e "   Health check:  ${GREEN}curl -k https://$SERVER_IP/nginx-health${NC}"
    echo -e "   API test:      ${GREEN}curl -k https://$SERVER_IP/api/v2/agents -H 'KEY: red'${NC}"
    echo ""
    echo -e "${CYAN}🪟 Merlino Configuration:${NC}"
    echo -e "   URL:           ${GREEN}https://$SERVER_IP${NC}"
    echo -e "   Port:          ${GREEN}443${NC}"
    echo -e "   API Key:       ${GREEN}red${NC} (or your configured key)"
    echo ""
    echo -e "${CYAN}🔄 Auto-start:${NC}"
    echo -e "   ✓ Caldera will start automatically on system boot"
    echo -e "   ✓ Nginx will start automatically on system boot"
    echo ""
    
    if [ "$TEST_MODE" = true ]; then
        echo -e "${CYAN}🧹 Cleanup Test Installation:${NC}"
        echo -e "   ${YELLOW}sudo systemctl stop caldera-test${NC}"
        echo -e "   ${YELLOW}sudo systemctl disable caldera-test${NC}"
        echo -e "   ${YELLOW}sudo rm -rf $CALDERA_DIR${NC}"
        echo -e "   ${YELLOW}sudo rm /etc/systemd/system/caldera-test.service${NC}"
        echo -e "   ${YELLOW}sudo rm /etc/nginx/sites-enabled/caldera-proxy${NC}"
        echo -e "   ${YELLOW}sudo userdel -r $CALDERA_USER${NC}"
        echo -e "   ${YELLOW}sudo systemctl daemon-reload && sudo systemctl restart nginx${NC}"
        echo ""
    fi
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
    detect_ip
    
    echo ""
    log_info "Starting deployment with:"
    log_info "  Server IP:      $SERVER_IP"
    log_info "  Caldera User:   $CALDERA_USER"
    log_info "  Install Dir:    $CALDERA_DIR"
    log_info "  Git Branch:     $BRANCH"
    echo ""
    
    install_dependencies
    create_caldera_user
    clone_or_update_caldera
    setup_python_environment
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
}

# Run main function
main "$@"
