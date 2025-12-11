# 🚀 Caldera Automatic Deployment

## Quick Start - One Command Deploy

Deploy Caldera + Nginx on a fresh Ubuntu server with a single command:

```bash
curl -sSL https://raw.githubusercontent.com/x3m-ai/caldera/master/start-caldera.sh | sudo bash
```

**That's it!** Caldera will be running with:
- ✅ Nginx HTTPS reverse proxy
- ✅ CORS configured for Merlino
- ✅ Auto-start on system boot
- ✅ SSL certificate generated
- ✅ Firewall configured

---

## What Gets Installed

### System Components
- Python 3 + venv
- Nginx web server
- OpenSSL for certificates
- Git
- UFW firewall

### Caldera Setup
- Installed in: `/opt/caldera`
- Running as user: `caldera`
- Virtual environment with all dependencies
- Systemd service for auto-start

### Nginx Configuration
- HTTPS on port 443
- HTTP redirect (80 → 443)
- Self-signed SSL certificate
- CORS headers for Merlino
- Reverse proxy to Caldera (port 8888)

---

## Manual Installation

If you prefer to clone first and then deploy:

```bash
# Clone repository
git clone https://github.com/x3m-ai/caldera.git
cd caldera

# Run deployment script
sudo bash start-caldera.sh
```

### Custom Options

```bash
# Specify server IP manually
sudo bash start-caldera.sh --ip 192.168.1.100

# Use custom user
sudo bash start-caldera.sh --user mycaldera

# Custom installation directory
sudo bash start-caldera.sh --dir /home/caldera

# Specific branch
sudo bash start-caldera.sh --branch develop
```

---

## Post-Installation

### Service Management

```bash
# Check status
systemctl status caldera
systemctl status nginx

# View logs
journalctl -u caldera -f
tail -f /var/log/nginx/caldera-access.log

# Restart services
systemctl restart caldera
systemctl restart nginx

# Stop services
systemctl stop caldera
systemctl stop nginx
```

### Testing

```bash
# Health check
curl -k https://YOUR_SERVER_IP/nginx-health

# API test
curl -k https://YOUR_SERVER_IP/api/v2/agents -H 'KEY: red'
```

### Export SSL Certificate (for Windows/Merlino)

```bash
# From Windows (PowerShell)
scp root@YOUR_SERVER_IP:/etc/nginx/ssl/caldera.crt C:\Users\YourName\caldera.crt

# Or copy manually
cat /etc/nginx/ssl/caldera.crt
```

---

## Configuration for Merlino

After deployment, configure Merlino Excel Add-in with:

- **Caldera URL:** `https://YOUR_SERVER_IP`
- **Port:** `443`
- **API Key:** `red` (or your configured key)

Don't forget to install the SSL certificate on Windows:
1. Double-click `caldera.crt`
2. Install to "Trusted Root Certification Authorities"

---

## Requirements

- **OS:** Ubuntu 20.04+ or Debian 11+
- **RAM:** 2GB minimum, 4GB recommended
- **Disk:** 10GB free space
- **Network:** Ports 80, 443 accessible

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  Windows (Merlino Excel Add-in)             │
│  https://merlino-addin...                   │
└──────────────────┬──────────────────────────┘
                   │ HTTPS + CORS
                   ▼
┌─────────────────────────────────────────────┐
│  Ubuntu Server                              │
│  ┌───────────────────────────────────────┐  │
│  │ Nginx :443 (HTTPS)                    │  │
│  │ - SSL Termination                     │  │
│  │ - CORS Headers                        │  │
│  │ - Systemd: nginx.service              │  │
│  └──────────────┬────────────────────────┘  │
│                 │ HTTP localhost            │
│  ┌──────────────▼────────────────────────┐  │
│  │ Caldera :8888 (HTTP)                  │  │
│  │ - Located: /opt/caldera               │  │
│  │ - User: caldera                       │  │
│  │ - Systemd: caldera.service            │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

---

## Auto-Start Configuration

Both Caldera and Nginx are configured to start automatically on system boot via systemd services:

- **Caldera Service:** `/etc/systemd/system/caldera.service`
- **Nginx Service:** Built-in systemd service

After system reboot, services will start automatically in this order:
1. Network is ready
2. Nginx starts
3. Caldera starts

---

## Troubleshooting

### Caldera Not Starting

```bash
# Check status
systemctl status caldera

# View logs
journalctl -u caldera -n 100

# Check if port is in use
ss -tuln | grep 8888

# Manually test
sudo -u caldera bash
cd /opt/caldera
source venv/bin/activate
python3 server.py --insecure
```

### Nginx Issues

```bash
# Test configuration
nginx -t

# Check logs
tail -f /var/log/nginx/caldera-error.log

# Reload configuration
systemctl reload nginx
```

### Firewall Blocking

```bash
# Check UFW status
ufw status

# Allow ports
ufw allow 443/tcp
ufw allow 80/tcp
```

### Certificate Issues

```bash
# Regenerate certificate
rm /etc/nginx/ssl/caldera.*
cd /opt/caldera
sudo bash setup_nginx_proxy.sh
```

---

## Uninstall

```bash
# Stop services
systemctl stop caldera nginx

# Disable auto-start
systemctl disable caldera

# Remove files
rm -rf /opt/caldera
rm /etc/systemd/system/caldera.service
rm /etc/nginx/sites-enabled/caldera-proxy
rm /etc/nginx/sites-available/caldera-proxy
rm -rf /etc/nginx/ssl/

# Remove user (optional)
userdel -r caldera

# Reload systemd
systemctl daemon-reload
```

---

## Security Notes

- Default configuration uses `--insecure` flag with default credentials
- For production, modify `/etc/systemd/system/caldera.service` to use proper config
- Consider using Let's Encrypt for production SSL certificates
- Change default API keys in Caldera configuration

---

## Support

- **Documentation:** [README_NGINX.md](README_NGINX.md)
- **Windows Setup:** [SETUP_WINDOWS.md](SETUP_WINDOWS.md)
- **Quick Reference:** [QUICK_START.txt](QUICK_START.txt)
- **GitHub Issues:** https://github.com/x3m-ai/caldera/issues

---

## License

Same as Caldera project license
