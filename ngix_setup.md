# Nginx Reverse Proxy Setup for Caldera + CORS

> **Destinatario:** Claude AI su Ubuntu Server dove è installato Caldera  
> **Obiettivo:** Configurare Nginx come reverse proxy HTTPS con CORS per permettere a Merlino Excel Add-in di comunicare con Caldera

---

## Contesto

**Merlino** è un Excel Add-in (Office.js) che gira in HTTPS e deve comunicare con **Caldera** per importare dati sugli agenti, operazioni, adversaries, e abilities.

**Problema attuale:**
- Merlino gira in HTTPS (browser requirement)
- Caldera gira in HTTP su porta 8888
- Browser blocca richieste HTTP da pagine HTTPS (Mixed Content)
- Browser blocca richieste cross-origin senza CORS headers

**Soluzione richiesta:**
Configurare **Nginx come reverse proxy** che:
1. Accetta connessioni HTTPS sulla porta 443
2. Aggiunge automaticamente CORS headers alle risposte
3. Inoltra le richieste a Caldera (HTTP localhost:8888)
4. Restituisce le risposte a Merlino con SSL + CORS

---

## Architettura Finale

```
┌─────────────────────────────────────────────────────────────┐
│  Windows (Client)                                           │
│  ┌──────────────────────────────────────┐                  │
│  │ Excel Desktop                        │                  │
│  │   ┌────────────────────────────┐     │                  │
│  │   │ Merlino Add-in (HTTPS)    │     │                  │
│  │   │ https://merlino-addin...  │     │                  │
│  │   └─────────────┬──────────────┘     │                  │
│  └─────────────────┼──────────────────────┘                │
└────────────────────┼─────────────────────────────────────────┘
                     │
                     │ HTTPS Request
                     │ GET /api/v2/agents
                     │ Header: KEY: ADMIN123
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Ubuntu Server (192.168.124.133)                            │
│  ┌──────────────────────────────────────┐                  │
│  │ Nginx :443 (HTTPS)                  │                  │
│  │ ┌────────────────────────────────┐   │                  │
│  │ │ SSL Termination               │   │                  │
│  │ │ CORS Headers Injection         │   │                  │
│  │ │ Reverse Proxy Logic            │   │                  │
│  │ └────────────┬───────────────────┘   │                  │
│  └──────────────┼───────────────────────┘                  │
│                 │                                           │
│                 │ HTTP Request (localhost)                  │
│                 │ GET /api/v2/agents                        │
│                 │ Header: KEY: ADMIN123                     │
│                 ▼                                           │
│  ┌──────────────────────────────────────┐                  │
│  │ Caldera :8888 (HTTP)                │                  │
│  │ http://127.0.0.1:8888                │                  │
│  │ (unchanged - rimane HTTP)            │                  │
│  └──────────────┬───────────────────────┘                  │
│                 │                                           │
│                 │ HTTP Response                             │
│                 │ JSON data                                 │
│                 ▼                                           │
│  ┌──────────────────────────────────────┐                  │
│  │ Nginx (aggiunge CORS headers)       │                  │
│  └──────────────┬───────────────────────┘                  │
└─────────────────┼─────────────────────────────────────────────┘
                  │
                  │ HTTPS Response
                  │ + Access-Control-Allow-Origin: *
                  │ + Access-Control-Allow-Methods: ...
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  Merlino (riceve risposta OK)                              │
└─────────────────────────────────────────────────────────────┘
```

---

## File da Creare

### 1. Nginx Configuration File

**Percorso:** `/etc/nginx/sites-available/caldera-proxy`

```nginx
# Nginx Reverse Proxy Configuration for Caldera + CORS
# Created for Merlino Excel Add-in integration

server {
    # Listen on port 443 with SSL/TLS
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    # Server identification
    server_name 192.168.124.133;
    
    # SSL Certificate configuration
    ssl_certificate /etc/nginx/ssl/caldera.crt;
    ssl_certificate_key /etc/nginx/ssl/caldera.key;
    
    # SSL Security settings (modern configuration)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # CORS Headers - Applied to ALL responses
    add_header 'Access-Control-Allow-Origin' '*' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS, PATCH' always;
    add_header 'Access-Control-Allow-Headers' 'Content-Type, KEY, Authorization, X-Requested-With, Accept, Origin' always;
    add_header 'Access-Control-Expose-Headers' 'Content-Length, Content-Type' always;
    add_header 'Access-Control-Max-Age' '86400' always;
    add_header 'Access-Control-Allow-Credentials' 'true' always;
    
    # Handle preflight OPTIONS requests
    if ($request_method = 'OPTIONS') {
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS, PATCH' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, KEY, Authorization, X-Requested-With, Accept, Origin' always;
        add_header 'Access-Control-Max-Age' '86400' always;
        add_header 'Content-Type' 'text/plain; charset=utf-8';
        add_header 'Content-Length' '0';
        return 204;
    }
    
    # Main proxy location - ALL requests go here
    location / {
        # Proxy to Caldera on localhost
        proxy_pass http://127.0.0.1:8888;
        
        # Preserve HTTP version
        proxy_http_version 1.1;
        
        # Forward headers from client to Caldera
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support (for future use)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeout settings for long-running operations
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Buffer settings
        proxy_buffering off;
        proxy_cache_bypass $http_upgrade;
        
        # Don't intercept errors from Caldera
        proxy_intercept_errors off;
    }
    
    # Health check endpoint (optional)
    location /nginx-health {
        access_log off;
        return 200 "Nginx proxy is running\n";
        add_header Content-Type text/plain;
    }
    
    # Access and error logs
    access_log /var/log/nginx/caldera-access.log;
    error_log /var/log/nginx/caldera-error.log warn;
}

# Redirect HTTP to HTTPS (optional but recommended)
server {
    listen 80;
    listen [::]:80;
    server_name 192.168.124.133;
    
    # Redirect all HTTP requests to HTTPS
    return 301 https://$host$request_uri;
}
```

---

### 2. Installation Script

**Percorso:** `/home/user/install-nginx-caldera-proxy.sh`

```bash
#!/bin/bash
# Nginx Reverse Proxy Setup Script for Caldera + CORS
# For Merlino Excel Add-in Integration
# Run with: sudo bash install-nginx-caldera-proxy.sh

set -e  # Exit on error

echo "=========================================="
echo "Nginx Reverse Proxy Setup for Caldera"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration variables
CALDERA_IP="192.168.124.133"
NGINX_SSL_DIR="/etc/nginx/ssl"
CERT_FILE="$NGINX_SSL_DIR/caldera.crt"
KEY_FILE="$NGINX_SSL_DIR/caldera.key"
NGINX_CONF_FILE="/etc/nginx/sites-available/caldera-proxy"
NGINX_ENABLED="/etc/nginx/sites-enabled/caldera-proxy"

echo -e "${YELLOW}Step 1/6: Checking prerequisites${NC}"
# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: Please run as root (use sudo)${NC}"
    exit 1
fi

# Check if Caldera is running on port 8888
echo "Checking if Caldera is running on port 8888..."
if netstat -tuln | grep -q ":8888 "; then
    echo -e "${GREEN}OK - Caldera is running on port 8888${NC}"
else
    echo -e "${YELLOW}WARNING: Caldera does not seem to be running on port 8888${NC}"
    echo "Please make sure Caldera is running before testing the proxy."
fi

echo ""
echo -e "${YELLOW}Step 2/6: Installing Nginx${NC}"
apt update
apt install -y nginx openssl

echo ""
echo -e "${YELLOW}Step 3/6: Creating SSL directory${NC}"
mkdir -p "$NGINX_SSL_DIR"
chmod 755 "$NGINX_SSL_DIR"

echo ""
echo -e "${YELLOW}Step 4/6: Generating SSL certificate${NC}"
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "Certificate already exists. Skipping generation."
    echo "To regenerate, delete files in $NGINX_SSL_DIR and run script again."
else
    echo "Generating self-signed certificate for $CALDERA_IP..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/C=IT/ST=State/L=City/O=X3M-AI/OU=Merlino/CN=$CALDERA_IP" \
        -addext "subjectAltName=IP:$CALDERA_IP"
    
    chmod 644 "$CERT_FILE"
    chmod 600 "$KEY_FILE"
    echo -e "${GREEN}Certificate generated successfully${NC}"
fi

echo ""
echo -e "${YELLOW}Step 5/6: Configuring Nginx${NC}"

# Create Nginx configuration
cat > "$NGINX_CONF_FILE" << 'NGINX_CONFIG_EOF'
# Nginx Reverse Proxy Configuration for Caldera + CORS
# Created for Merlino Excel Add-in integration

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name 192.168.124.133;
    
    ssl_certificate /etc/nginx/ssl/caldera.crt;
    ssl_certificate_key /etc/nginx/ssl/caldera.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    add_header 'Access-Control-Allow-Origin' '*' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS, PATCH' always;
    add_header 'Access-Control-Allow-Headers' 'Content-Type, KEY, Authorization, X-Requested-With, Accept, Origin' always;
    add_header 'Access-Control-Expose-Headers' 'Content-Length, Content-Type' always;
    add_header 'Access-Control-Max-Age' '86400' always;
    add_header 'Access-Control-Allow-Credentials' 'true' always;
    
    if ($request_method = 'OPTIONS') {
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS, PATCH' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, KEY, Authorization, X-Requested-With, Accept, Origin' always;
        add_header 'Access-Control-Max-Age' '86400' always;
        add_header 'Content-Type' 'text/plain; charset=utf-8';
        add_header 'Content-Length' '0';
        return 204;
    }
    
    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        proxy_buffering off;
        proxy_cache_bypass $http_upgrade;
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
    server_name 192.168.124.133;
    return 301 https://$host$request_uri;
}
NGINX_CONFIG_EOF

echo "Configuration file created at $NGINX_CONF_FILE"

# Enable the site
if [ -L "$NGINX_ENABLED" ]; then
    echo "Site already enabled. Skipping symbolic link creation."
else
    ln -s "$NGINX_CONF_FILE" "$NGINX_ENABLED"
    echo "Site enabled via symbolic link"
fi

# Disable default Nginx site
if [ -L "/etc/nginx/sites-enabled/default" ]; then
    rm /etc/nginx/sites-enabled/default
    echo "Default Nginx site disabled"
fi

# Test Nginx configuration
echo ""
echo "Testing Nginx configuration..."
nginx -t

echo ""
echo -e "${YELLOW}Step 6/6: Configuring firewall and starting Nginx${NC}"

# Configure UFW firewall if active
if command -v ufw &> /dev/null; then
    if ufw status | grep -q "Status: active"; then
        echo "Configuring UFW firewall..."
        ufw allow 443/tcp comment 'Nginx HTTPS for Caldera proxy'
        ufw allow 80/tcp comment 'Nginx HTTP redirect'
        ufw reload
        echo -e "${GREEN}Firewall rules added${NC}"
    fi
fi

# Restart Nginx
echo "Restarting Nginx..."
systemctl restart nginx
systemctl enable nginx

# Check Nginx status
if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}SUCCESS: Nginx is running${NC}"
else
    echo -e "${RED}ERROR: Nginx failed to start${NC}"
    echo "Check logs with: journalctl -xeu nginx.service"
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}Installation Complete!${NC}"
echo "=========================================="
echo ""
echo "Nginx Reverse Proxy Status:"
echo "  - HTTPS Port: 443"
echo "  - Proxying to: http://127.0.0.1:8888 (Caldera)"
echo "  - CORS: Enabled"
echo "  - SSL Certificate: $CERT_FILE"
echo ""
echo "Next Steps:"
echo "1. Export certificate to Windows:"
echo "   scp root@192.168.124.133:$CERT_FILE ~/caldera-cert.crt"
echo ""
echo "2. Install certificate on Windows (double-click and install to Trusted Root CA)"
echo ""
echo "3. Update Merlino Settings taskpane:"
echo "   - Caldera URL: https://192.168.124.133"
echo "   - Port: 443 (default HTTPS)"
echo "   - API Key: (your Caldera API key)"
echo ""
echo "4. Test connection from Merlino:"
echo "   - Open Settings taskpane"
echo "   - Click 'Test Connection' button"
echo ""
echo "Testing Commands:"
echo "  - Health check: curl -k https://192.168.124.133/nginx-health"
echo "  - Caldera API: curl -k https://192.168.124.133/api/v2/agents -H 'KEY: ADMIN123'"
echo "  - View logs: tail -f /var/log/nginx/caldera-access.log"
echo ""
echo "Troubleshooting:"
echo "  - Check Nginx: systemctl status nginx"
echo "  - Check Caldera: netstat -tuln | grep 8888"
echo "  - View errors: tail -f /var/log/nginx/caldera-error.log"
echo ""