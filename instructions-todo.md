# Testing Guide for start-caldera.sh

## Script Purpose

The `start-caldera.sh` script is an **automated deployment and startup tool** for the Caldera C2 Framework with Nginx reverse proxy integration. It's designed for **infrastructure teams** deploying Caldera to serve the **Merlino Excel Add-in**.

### Primary Goals

1. **One-command deployment** on fresh Ubuntu servers
2. **HTTPS endpoint** with self-signed SSL certificates (10-year validity)
3. **CORS-enabled Nginx reverse proxy** for cross-origin requests from Excel
4. **Systemd auto-start** configuration for both Nginx and Caldera
5. **Smart detection** - works on both fresh installs and existing installations

### Target Users

- Infrastructure/DevOps teams
- Security researchers deploying Caldera
- Organizations using Merlino Excel Add-in for C2 operations

---

## Deliverables

### What the Script Must Deliver

1. **Fully functional Caldera installation** at `/opt/caldera` (or custom directory)
2. **Nginx HTTPS proxy** listening on port 443
3. **SSL certificate** at `/etc/nginx/ssl/caldera.crt` (10 years validity)
4. **Systemd services** configured for auto-start on boot:
   - `caldera.service`
   - `nginx.service`
5. **Firewall rules** (UFW) allowing ports 443, 80, and SSH
6. **CORS headers** configured in Nginx for Merlino integration
7. **API endpoint** accessible at `https://SERVER_IP/api/v2/*`
8. **Health check endpoint** at `https://SERVER_IP/nginx-health`

### Expected Outcome

After successful execution, the user should see:
- ✅ Caldera running on localhost:8888
- ✅ Nginx proxying HTTPS (443) → Caldera (8888)
- ✅ Services enabled for auto-start
- ✅ Detailed completion message with:
  - Server IP and URLs
  - SSL certificate location and installation instructions
  - Merlino configuration details
  - Service management commands
  - Test commands

---

## Success Criteria

### Functional Requirements

| Requirement | Test Command | Expected Result |
|------------|--------------|-----------------|
| Caldera service running | `systemctl is-active caldera` | `active` |
| Nginx service running | `systemctl is-active nginx` | `active` |
| Port 443 listening | `ss -tuln \| grep :443` | Shows LISTEN |
| Port 8888 listening | `ss -tuln \| grep :8888` | Shows LISTEN |
| SSL certificate exists | `ls -l /etc/nginx/ssl/caldera.crt` | File exists |
| Health check works | `curl -k https://localhost/nginx-health` | "Nginx proxy is running" |
| API responds (no auth) | `curl -k https://localhost/api/v2/agents` | HTTP 401 |
| API responds (with key) | `curl -k https://localhost/api/v2/agents -H 'KEY: ADMIN123'` | `[]` (empty array) |
| CORS headers present | `curl -Ik https://localhost/api/v2/agents` | `access-control-allow-origin: *` |
| Auto-start enabled | `systemctl is-enabled caldera nginx` | `enabled` for both |
| Firewall configured | `sudo ufw status` | Port 443/tcp ALLOW |

### Non-Functional Requirements

1. **Execution time**: < 10 minutes on typical broadband connection
2. **Idempotent**: Running twice should not cause errors
3. **Verbose output**: All operations visible (set -x enabled)
4. **Error handling**: Clear error messages on failure
5. **Rollback safe**: Does not break existing installations

---

## Test Scenarios

### Test 1: Fresh Ubuntu Installation

**Target**: Clean Ubuntu 22.04/24.04 server with no prior Caldera installation

**Prerequisites**:
- Fresh Ubuntu server (minimal or server edition)
- Root/sudo access
- Internet connection
- 2GB+ RAM, 10GB+ disk space

**Execution**:
```bash
wget -qO- https://raw.githubusercontent.com/x3m-ai/caldera/master/start-caldera.sh | sudo bash
```

**Expected Duration**: 5-10 minutes

**Success Indicators**:
1. Script shows version banner (1.2.0+)
2. Detects IP automatically
3. Shows "Fresh installation - will install everything"
4. Installs all dependencies with visible output
5. Clones Caldera repository with progress bar
6. Installs Python packages (visible pip output)
7. Generates SSL certificate
8. Configures Nginx
9. Creates systemd services
10. Configures firewall
11. Starts services
12. Shows completion banner with all details

**Validation**:
Run all commands from "Functional Requirements" table above.

---

### Test 2: Existing Installation (Restart)

**Target**: Server where Caldera is already installed but not running

**Execution**:
```bash
cd /opt/caldera  # or wherever Caldera is installed
sudo bash start-caldera.sh
```

**Expected Behavior**:
1. Detects existing installation
2. Shows "Update/Start existing" mode
3. Checks Nginx status
4. Starts Nginx if not running
5. Checks Caldera status
6. Starts Caldera if not running
7. Ensures auto-start is configured
8. Shows completion message

**Success Indicators**:
- No re-cloning or re-installation
- Services start successfully
- Auto-start verified

---

### Test 3: Custom Configuration

**Target**: Installation with custom parameters

**Execution**:
```bash
sudo bash start-caldera.sh --ip 10.0.0.50 --user mycaldera --dir /home/caldera
```

**Expected Behavior**:
1. Uses provided IP (10.0.0.50) instead of auto-detect
2. Creates user "mycaldera"
3. Installs to /home/caldera
4. SSL certificate generated for 10.0.0.50

**Validation**:
```bash
# Check custom IP in Nginx config
sudo grep "10.0.0.50" /etc/nginx/sites-available/caldera-proxy

# Check custom user
ps aux | grep mycaldera

# Check custom directory
ls -la /home/caldera
```

---

### Test 4: Test Mode (Parallel Installation)

**Target**: Test installation alongside production

**Execution**:
```bash
sudo bash start-caldera.sh --test
```

**Expected Behavior**:
1. Uses different ports (8443, 8889)
2. Creates test user (caldera-test)
3. Installs to /opt/caldera-test
4. Creates caldera-test.service
5. Does not interfere with production

**Validation**:
```bash
# Both services should be running
systemctl status caldera caldera-test

# Different ports
ss -tuln | grep -E "(443|8443|8888|8889)"
```

---

### Test 5: Windows/Merlino Integration

**Target**: Verify Merlino Excel Add-in can connect

**Prerequisites**:
- Caldera deployed and running
- Windows machine with Excel
- Merlino Excel Add-in installed
- SSL certificate imported on Windows

**Steps**:

1. **Export certificate from Linux**:
```bash
# On Linux server
scp root@CALDERA_IP:/etc/nginx/ssl/caldera.crt ~/Desktop/
```

2. **Install certificate on Windows**:
   - Double-click `caldera.crt`
   - Click "Install Certificate"
   - Select "Local Machine"
   - Choose "Trusted Root Certification Authorities"
   - Complete wizard
   - Restart Excel

3. **Test from PowerShell**:
```powershell
# Test connectivity
Test-NetConnection -ComputerName CALDERA_IP -Port 443

# Test health endpoint
Invoke-WebRequest -Uri "https://CALDERA_IP/nginx-health" -SkipCertificateCheck

# Test API
$headers = @{ "KEY" = "ADMIN123" }
Invoke-WebRequest -Uri "https://CALDERA_IP/api/v2/agents" -Headers $headers -SkipCertificateCheck
```

4. **Configure Merlino**:
   - Open Excel
   - Merlino Add-in settings
   - Caldera URL: `https://CALDERA_IP`
   - API Key: `ADMIN123` (or from conf/default.yml)
   - Test connection

**Success Indicators**:
- PowerShell tests return HTTP 200
- Merlino connects successfully
- No SSL certificate errors in Excel

---

## Troubleshooting Common Issues

### Issue 1: Script Hangs During Package Installation

**Symptoms**: Script stops after "Installing system dependencies"

**Diagnosis**:
```bash
# Check if APT is locked
sudo fuser /var/lib/dpkg/lock-frontend

# Check apt processes
ps aux | grep apt
```

**Solution**:
- Wait for other APT processes to complete
- Script has 60s timeout for lock
- Or kill other apt processes: `sudo killall apt apt-get`

---

### Issue 2: Caldera Service Fails to Start

**Symptoms**: `systemctl status caldera` shows failed/inactive

**Diagnosis**:
```bash
# Check logs
sudo journalctl -u caldera -n 50

# Common issues:
# - Port 8888 already in use
# - Permission errors
# - Missing Python dependencies
```

**Solution**:
```bash
# Check port availability
ss -tuln | grep 8888

# Kill processes on port 8888
sudo fuser -k 8888/tcp

# Restart service
sudo systemctl restart caldera
```

---

### Issue 3: 502 Bad Gateway from Nginx

**Symptoms**: Health check works, but API returns 502

**Diagnosis**:
```bash
# Check Nginx config
sudo nginx -t

# Check if Caldera is running
curl http://localhost:8888/api/v2/agents

# Check Nginx error log
sudo tail -f /var/log/nginx/caldera-error.log
```

**Solution**:
- Verify proxy_pass points to correct port (8888)
- Ensure Caldera is running
- Check firewall isn't blocking internal connections

---

### Issue 4: Windows Cannot Connect

**Symptoms**: Merlino/PowerShell cannot reach Caldera

**Diagnosis**:
```bash
# On Linux - check if port is open
sudo ufw status | grep 443

# Check if accessible from Linux
curl -k https://SERVER_IP/nginx-health

# On Windows - test connectivity
ping SERVER_IP
Test-NetConnection -ComputerName SERVER_IP -Port 443
```

**Solution**:
1. **Firewall**: Ensure port 443 is open: `sudo ufw allow 443/tcp`
2. **Network**: Verify Windows and Linux are on same network/VLAN
3. **Certificate**: Install SSL certificate on Windows
4. **DNS**: Use IP address instead of hostname

---

## Performance Benchmarks

### Installation Time Breakdown

| Phase | Expected Duration | Notes |
|-------|------------------|-------|
| Package updates | 30-60s | Depends on repository speed |
| Package installation | 1-2 min | Python, Nginx, Git, etc. |
| Git clone | 1-2 min | Caldera + all plugins |
| Python dependencies | 2-4 min | Largest phase, 50+ packages |
| SSL generation | 5-10s | RSA 4096-bit |
| Nginx configuration | 5s | Config generation + test |
| Service setup | 10s | Systemd service creation |
| Firewall config | 5s | UFW rules |
| **Total** | **5-10 min** | On typical connection |

### Resource Usage

| Resource | Fresh Install | Running State |
|----------|--------------|---------------|
| Disk | ~1.5 GB | ~1.5 GB |
| RAM | 200-300 MB (install) | 150-250 MB (runtime) |
| CPU | 1-2 cores | 0.1-0.5 core (idle) |

---

## Regression Testing Checklist

Before releasing a new version, verify:

- [ ] Fresh Ubuntu 22.04 installation works
- [ ] Fresh Ubuntu 24.04 installation works
- [ ] Existing installation detection works
- [ ] Restart on existing installation works
- [ ] Custom IP parameter works
- [ ] Custom user parameter works
- [ ] Custom directory parameter works
- [ ] Test mode (--test) works
- [ ] SSL certificate is 10 years validity
- [ ] Nginx CORS headers are present
- [ ] Systemd auto-start is configured
- [ ] Firewall rules are applied
- [ ] Health check endpoint responds
- [ ] API endpoint responds with auth
- [ ] API returns 401 without auth
- [ ] Windows PowerShell can connect
- [ ] Merlino Excel Add-in can connect
- [ ] Script is idempotent (can run twice)
- [ ] Verbose output shows all operations
- [ ] Error messages are clear
- [ ] Version number displayed in banner

---

## Reporting Issues

When reporting issues, provide:

1. **Script version**: From banner or `grep SCRIPT_VERSION start-caldera.sh`
2. **OS version**: `lsb_release -a` or `cat /etc/os-release`
3. **Execution mode**: Fresh install, existing, test mode, custom params
4. **Full output**: Complete terminal output including verbose traces
5. **Service status**:
   ```bash
   systemctl status caldera nginx
   sudo journalctl -u caldera -n 100
   ```
6. **Network info**:
   ```bash
   ip addr show
   ss -tuln | grep -E "(443|8888)"
   sudo ufw status verbose
   ```

---

## Version History

### v1.3.0 (Current)
- **Clean verbose output**: Colors defined before `set -x` to avoid escape sequences
- **Step separators**: Clear visual separators for each deployment phase
- **Better symbols**: ✓ for success, ⚠ for warnings, ✗ for errors
- **Structured logging**: log_step() function for major phases

### v1.2.0
- Full verbose mode with `set -x`
- Removed all output suppressions
- APT lock detection and waiting
- Better error handling
- Progress messages for sysadmin

### v1.1.0
- Added version tracking
- Banner displays version number
- Usage documentation updates

### v1.0.0 (Initial)
- Fresh installation support
- Existing installation detection
- Nginx reverse proxy setup
- SSL certificate generation (10 years)
- CORS configuration
- Systemd auto-start
- UFW firewall configuration

---

## Future Enhancements

Potential improvements for future versions:

- [ ] Support for Let's Encrypt certificates
- [ ] Docker deployment option
- [ ] Support for other Linux distros (CentOS, Debian)
- [ ] Health monitoring integration
- [ ] Backup/restore functionality
- [ ] Multi-node cluster setup
- [ ] Performance tuning options
- [ ] Logging configuration options
- [ ] Integration with monitoring tools (Prometheus, Grafana)

---

## Quick Reference

### One-Line Install
```bash
wget -qO- https://raw.githubusercontent.com/x3m-ai/caldera/master/start-caldera.sh | sudo bash
```

### Essential Commands
```bash
# Check status
systemctl status caldera nginx

# Restart services
sudo systemctl restart caldera nginx

# View logs
sudo journalctl -u caldera -f

# Test endpoints
curl -k https://localhost/nginx-health
curl -k https://localhost/api/v2/agents -H 'KEY: ADMIN123'

# Check ports
ss -tuln | grep -E "(443|8888)"

# Firewall status
sudo ufw status verbose
```

### Configuration Files
- Caldera: `/opt/caldera/conf/default.yml`
- Nginx: `/etc/nginx/sites-available/caldera-proxy`
- Systemd: `/etc/systemd/system/caldera.service`
- SSL Cert: `/etc/nginx/ssl/caldera.crt`
- Logs: `/var/log/nginx/caldera-*.log`

---

## Support

For issues or questions:
- GitHub: https://github.com/x3m-ai/caldera
- Check QUICK_INSTALL.md for basic setup
- Check DEPLOYMENT.md for advanced configuration
- Check SETUP_WINDOWS.md for Merlino integration
