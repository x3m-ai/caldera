# Nginx Reverse Proxy per Merlino + Caldera

## 🎯 Panoramica

Sistema di integrazione automatica tra **Merlino** (Excel Add-in su Windows) e **Caldera** (Ubuntu Server) tramite Nginx reverse proxy con HTTPS e CORS.

## 🚀 Setup Automatico

### Metodo 1: Avvio Automatico con Caldera (RACCOMANDATO)

Quando avvii Caldera, il sistema controllerà automaticamente Nginx e lo configurerà se necessario:

```bash
sudo python3 server.py
```

**Cosa succede:**
1. ✓ Controlla se Nginx è installato (se no, lo installa)
2. ✓ Genera certificato SSL self-signed
3. ✓ Crea configurazione Nginx con CORS
4. ✓ Configura firewall (UFW)
5. ✓ Avvia Nginx
6. ✓ Avvia Caldera normalmente

**Requisiti:**
- Permessi root (usa `sudo`)
- Connessione internet (per installare Nginx se necessario)

### Metodo 2: Setup Manuale

Se preferisci configurare Nginx separatamente:

```bash
sudo bash setup_nginx_proxy.sh
```

## 📋 Architettura

```
┌────────────────────────────────────────────┐
│  Windows (Merlino Excel Add-in)            │
│  https://merlino-addin...                  │
└──────────────────┬─────────────────────────┘
                   │ HTTPS + CORS
                   ▼
┌────────────────────────────────────────────┐
│  Ubuntu Server (192.168.124.133)           │
│  ┌──────────────────────────────────────┐  │
│  │ Nginx :443 (HTTPS)                  │  │
│  │ + SSL Termination                   │  │
│  │ + CORS Headers                      │  │
│  └─────────────┬────────────────────────┘  │
│                │ HTTP localhost            │
│  ┌─────────────▼────────────────────────┐  │
│  │ Caldera :8888 (HTTP)                │  │
│  │ http://127.0.0.1:8888                │  │
│  └──────────────────────────────────────┘  │
└────────────────────────────────────────────┘
```

## 🔧 Configurazione Merlino (Windows)

### Step 1: Esporta Certificato SSL

Da Ubuntu:
```bash
# Scopri l'IP del server Ubuntu se non lo conosci
ip addr show

# Il certificato è in:
/etc/nginx/ssl/caldera.crt
```

Da Windows (PowerShell o CMD):
```bash
scp morgana@192.168.124.133:/etc/nginx/ssl/caldera.crt C:\Users\TuoNome\caldera-cert.crt
```

### Step 2: Installa Certificato su Windows

1. Doppio click su `caldera-cert.crt`
2. Click su "Install Certificate..."
3. Scegli "Local Machine"
4. Scegli "Place all certificates in the following store"
5. Browse → "Trusted Root Certification Authorities"
6. Next → Finish

**⚠️ IMPORTANTE:** Senza questo step, il browser bloccherà le richieste HTTPS!

### Step 3: Configura Merlino Settings

Nel taskpane Settings di Merlino:

```
Caldera URL: https://192.168.124.133
Port: 443
API Key: [la tua API key di Caldera]
```

### Step 4: Test Connessione

1. Apri Merlino in Excel
2. Vai nel taskpane Settings
3. Click su "Test Connection"
4. ✓ Dovresti vedere "Connection successful!"

## 🧪 Testing

### Da Ubuntu

```bash
# Test health check Nginx
curl -k https://192.168.124.133/nginx-health

# Test API Caldera (sostituisci ADMIN123 con la tua key)
curl -k https://192.168.124.133/api/v2/agents -H 'KEY: ADMIN123'

# Verifica Nginx status
systemctl status nginx

# Verifica Caldera status
netstat -tuln | grep 8888

# Log in real-time
tail -f /var/log/nginx/caldera-access.log
tail -f /var/log/nginx/caldera-error.log
```

### Da Windows (PowerShell)

```powershell
# Test health check
Invoke-WebRequest -Uri https://192.168.124.133/nginx-health -SkipCertificateCheck

# Test API
$headers = @{ "KEY" = "ADMIN123" }
Invoke-RestMethod -Uri https://192.168.124.133/api/v2/agents -Headers $headers -SkipCertificateCheck
```

## 📂 File Creati

```
/etc/nginx/
├── sites-available/
│   └── caldera-proxy          # Configurazione Nginx
├── sites-enabled/
│   └── caldera-proxy -> ...   # Link simbolico
└── ssl/
    ├── caldera.crt            # Certificato SSL
    └── caldera.key            # Chiave privata

/home/morgana/caldera/
├── app/utility/
│   └── nginx_manager.py       # Modulo Python per gestione Nginx
├── setup_nginx_proxy.sh       # Script standalone di setup
└── README_NGINX.md            # Questa documentazione
```

## 🔒 Sicurezza

### Certificato SSL

- **Self-signed certificate** generato automaticamente
- Valido per 365 giorni
- Subject Alternative Name (SAN) con IP del server
- Chiave RSA 4096-bit

### CORS Headers

Nginx aggiunge automaticamente:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH
Access-Control-Allow-Headers: Content-Type, KEY, Authorization, ...
Access-Control-Allow-Credentials: true
```

### Firewall

Se UFW è attivo, vengono aperte automaticamente:
- Porta 443/tcp (HTTPS)
- Porta 80/tcp (redirect a HTTPS)

## 🐛 Troubleshooting

### Nginx non si avvia

```bash
# Controlla errori configurazione
sudo nginx -t

# Controlla log di sistema
sudo journalctl -xeu nginx.service

# Controlla log errori Nginx
sudo tail -f /var/log/nginx/caldera-error.log
```

### Caldera non risponde

```bash
# Verifica che Caldera sia in ascolto
sudo netstat -tuln | grep 8888

# Riavvia Caldera
cd /home/morgana/caldera
sudo python3 server.py
```

### Merlino non si connette

1. **Verifica certificato installato** su Windows
2. **Verifica URL** in Merlino Settings: `https://192.168.124.133`
3. **Verifica API key** corretta
4. **Controlla firewall Windows** (potrebbe bloccare richieste HTTPS)
5. **Test da browser** su Windows: `https://192.168.124.133/nginx-health`

### Porta 443 già in uso

```bash
# Scopri cosa usa la porta 443
sudo netstat -tulnp | grep :443

# Se necessario, ferma il servizio conflittuale
sudo systemctl stop <servizio>
```

## 🔄 Aggiornamenti

### Rigenera Certificato SSL

```bash
# Rimuovi certificato esistente
sudo rm /etc/nginx/ssl/caldera.crt
sudo rm /etc/nginx/ssl/caldera.key

# Riavvia Caldera per rigenerarlo
sudo python3 server.py
```

### Cambia IP Server

Modifica in `app/utility/nginx_manager.py`:

```python
nginx_mgr = NginxManager(
    caldera_ip="192.168.124.XXX",  # <-- Nuovo IP
    caldera_port=8888
)
```

### Disabilita Setup Automatico

Commenta in `server.py` (funzione `run_tasks`):

```python
# nginx_mgr = NginxManager(...)
# nginx_mgr.ensure_running()
```

## 📊 Performance

- **Latenza aggiunta:** ~2-5ms (overhead Nginx reverse proxy)
- **Throughput:** Illimitato per API REST
- **WebSocket:** Supportato (per future estensioni)
- **Keep-Alive:** Abilitato
- **Buffer:** Disabilitato per risposte real-time

## 📞 Supporto

Per problemi o domande:

1. Controlla questa documentazione
2. Verifica i log: `/var/log/nginx/caldera-error.log`
3. Verifica il README originale: `ngix_setup.md`

## 📝 Note Tecniche

### Timeout

```nginx
proxy_connect_timeout 300s;
proxy_send_timeout 300s;
proxy_read_timeout 300s;
```

Configurato per operazioni lunghe (es. download payload, operazioni complesse).

### HTTP/2

Abilitato per prestazioni migliori:
```nginx
listen 443 ssl http2;
```

### SSL Protocols

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

Solo protocolli moderni e sicuri.

## ✅ Checklist Installazione

- [ ] Ubuntu Server con Caldera installato
- [ ] Permessi sudo/root
- [ ] Caldera funzionante su porta 8888
- [ ] IP statico o conosciuto
- [ ] Firewall configurato (se necessario)
- [ ] Nginx installato (o permessi per installarlo)
- [ ] Certificato esportato su Windows
- [ ] Certificato installato su Windows (Trusted Root CA)
- [ ] Merlino configurato con URL HTTPS
- [ ] Test connessione riuscito

## 🎉 Risultato Atteso

Dopo il setup:
- ✓ Caldera avviato su `http://127.0.0.1:8888`
- ✓ Nginx proxy su `https://192.168.124.133`
- ✓ CORS abilitato
- ✓ Merlino può comunicare con Caldera
- ✓ Tutto automatico ad ogni avvio di Caldera
