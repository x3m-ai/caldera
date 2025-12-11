# ⚡ Quick Installation Guide

## One-Command Installation (Recommended)

Install Caldera + Nginx on a fresh Ubuntu server with auto-start configuration:

```bash
curl -sSL https://raw.githubusercontent.com/x3m-ai/caldera/master/start-caldera.sh | sudo bash
```

**What this does:**
- ✅ Installs all dependencies (Python, Nginx, Git, etc.)
- ✅ Clones Caldera repository with all plugins
- ✅ Sets up Python virtual environment
- ✅ Generates 10-year SSL certificate
- ✅ Configures Nginx reverse proxy with CORS
- ✅ Creates systemd service for auto-start on boot
- ✅ Starts all services automatically

**Time:** ~5-10 minutes on a clean Ubuntu system

---

## Existing Installation

If Caldera is already installed, the script will:
- ✅ Check and start Nginx if not running
- ✅ Check and start Caldera if not running
- ✅ Ensure auto-start is configured
- ✅ Display connection information

Simply run:
```bash
cd /path/to/caldera
sudo bash start-caldera.sh
```

---

## Custom Options

### Specify Server IP
```bash
curl -sSL https://raw.githubusercontent.com/x3m-ai/caldera/master/start-caldera.sh | sudo bash -s -- --ip 192.168.1.100
```

### Clone First, Deploy Later
```bash
git clone https://github.com/x3m-ai/caldera.git --recursive
cd caldera
sudo bash start-caldera.sh
```

### Advanced Options
```bash
sudo bash start-caldera.sh --ip 192.168.1.100      # Custom IP
sudo bash start-caldera.sh --user mycaldera        # Custom user
sudo bash start-caldera.sh --dir /custom/path      # Custom directory
sudo bash start-caldera.sh --branch develop        # Specific branch
```

---

## After Installation

### Access Caldera
- **URL:** `https://YOUR_SERVER_IP`
- **Default Credentials:** `red / admin`
- **API Key:** Check `conf/default.yml` (default: `ADMIN123`)

### Service Management
```bash
# Check status
systemctl status caldera nginx

# Restart services
systemctl restart caldera
systemctl restart nginx

# View logs
journalctl -u caldera -f
tail -f /var/log/nginx/caldera-access.log
```

### SSL Certificate for Windows/Merlino
```bash
# Export certificate from Linux server
scp root@YOUR_SERVER_IP:/etc/nginx/ssl/caldera.crt ~/Desktop/

# On Windows:
# 1. Double-click caldera.crt
# 2. Click "Install Certificate"
# 3. Select "Local Machine"
# 4. Choose "Trusted Root Certification Authorities"
# 5. Complete the wizard
# 6. Restart Excel
```

---

## Testing

### From Linux Server
```bash
# Nginx health check
curl -k https://localhost/nginx-health

# Caldera API
curl -k https://localhost/api/v2/agents -H 'KEY: ADMIN123'
```

### From Windows Client
```powershell
# Test connection (PowerShell)
Invoke-WebRequest -Uri "https://YOUR_SERVER_IP/nginx-health" -SkipCertificateCheck
```

---

## Troubleshooting

### Services Not Running
```bash
# Check if services are active
systemctl is-active caldera nginx

# Check for errors
journalctl -u caldera -n 50
journalctl -u nginx -n 50
```

### Port Conflicts
```bash
# Check what's using ports
ss -tuln | grep -E '(443|8888)'

# Kill conflicting process
sudo systemctl stop <service-name>
```

### Firewall Issues
```bash
# Check firewall status
sudo ufw status

# Allow HTTPS if needed
sudo ufw allow 443/tcp
```

### Regenerate SSL Certificate
```bash
sudo rm /etc/nginx/ssl/caldera.*
sudo bash start-caldera.sh  # Will regenerate
```

---

## Manual Installation (Advanced)

If you prefer manual setup, see [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

For Windows/Merlino integration, see [SETUP_WINDOWS.md](SETUP_WINDOWS.md).
