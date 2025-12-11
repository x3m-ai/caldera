# 🚀 Setup Completato - Istruzioni per Windows/Merlino

## ✅ Cosa è stato fatto su Ubuntu

Il sistema Caldera ora include **setup automatico di Nginx** con:

1. ✓ Modulo Python `nginx_manager.py` per gestione automatica
2. ✓ Integrazione in `server.py` - controllo all'avvio
3. ✓ Script standalone `setup_nginx_proxy.sh` (opzionale)
4. ✓ Documentazione completa in `README_NGINX.md`

## 🎯 Come Funziona

Quando avvii Caldera su Ubuntu:

```bash
sudo python3 server.py
```

Il sistema **automaticamente**:
- Controlla se Nginx è installato (se no, lo installa)
- Genera certificato SSL self-signed
- Crea configurazione Nginx con CORS
- Configura firewall
- Avvia Nginx su porta 443
- Avvia Caldera su porta 8888

**Risultato:** Caldera accessibile via HTTPS con CORS da Merlino!

## 📋 Cosa Devi Fare su Windows

### Step 1: Ottieni il Certificato SSL

Da Windows PowerShell:

```powershell
# Sostituisci con l'IP corretto se diverso
scp morgana@192.168.124.133:/etc/nginx/ssl/caldera.crt C:\Users\TuoNome\caldera-cert.crt
```

**Nota:** Ti verrà chiesta la password dell'utente `morgana` su Ubuntu.

### Step 2: Installa il Certificato

1. Vai in `C:\Users\TuoNome\`
2. Doppio click su `caldera-cert.crt`
3. Click "Install Certificate..."
4. Scegli **"Local Machine"**
5. Scegli **"Place all certificates in the following store"**
6. Click "Browse" → seleziona **"Trusted Root Certification Authorities"**
7. Click "Next" → "Finish"

**⚠️ CRITICO:** Senza questo, Excel/Merlino bloccherà tutte le richieste HTTPS!

### Step 3: Configura Merlino

Nel taskpane **Settings** di Merlino:

```
Caldera URL: https://192.168.124.133
Port: 443
API Key: [la tua key di Caldera - es. ADMIN123]
```

**IMPORTANTE:** 
- URL deve iniziare con `https://`
- NON includere la porta nell'URL (usa il campo Port separato)
- Porta deve essere `443`

### Step 4: Test Connessione

1. Apri Excel e carica Merlino
2. Vai nel taskpane **Settings**
3. Click sul pulsante **"Test Connection"**
4. Dovresti vedere: ✓ **"Connection successful!"**

## 🧪 Test Rapidi

### Da Windows (Browser)

Apri nel browser:
```
https://192.168.124.133/nginx-health
```

Dovresti vedere: `Nginx proxy is running`

### Da Windows (PowerShell)

```powershell
# Health check
Invoke-WebRequest -Uri https://192.168.124.133/nginx-health

# Test API Caldera (sostituisci la key)
$headers = @{ "KEY" = "ADMIN123" }
Invoke-RestMethod -Uri https://192.168.124.133/api/v2/agents -Headers $headers
```

## 🐛 Troubleshooting

### Errore: "Unable to connect"

1. **Verifica Caldera attivo** (chiedi conferma a Ubuntu)
2. **Verifica IP corretto**: `192.168.124.133`
3. **Ping al server**:
   ```powershell
   ping 192.168.124.133
   ```

### Errore: "Certificate not trusted"

1. **Reinstalla certificato** (ripeti Step 2)
2. **Verifica installato in "Trusted Root CA"** non in altri store
3. **Riavvia Excel** dopo installazione certificato

### Errore: "CORS policy blocked"

- Questo è risolto automaticamente da Nginx
- Se vedi questo errore, Nginx potrebbe non essere attivo
- Chiedi di verificare su Ubuntu: `systemctl status nginx`

### Firewall Windows blocca connessione

```powershell
# Aggiungi regola firewall Windows
New-NetFirewallRule -DisplayName "Caldera HTTPS" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
```

## 📊 Endpoint Disponibili

Una volta configurato, Merlino può accedere a:

```
https://192.168.124.133/api/v2/agents
https://192.168.124.133/api/v2/operations
https://192.168.124.133/api/v2/adversaries
https://192.168.124.133/api/v2/abilities
https://192.168.124.133/api/v2/objectives
https://192.168.124.133/api/v2/planners
https://192.168.124.133/api/v2/sources
```

Tutti con:
- ✓ HTTPS
- ✓ CORS abilitato
- ✓ Header `KEY` per autenticazione

## 🔄 Workflow Normale

### Avvio Giornaliero

**Su Ubuntu:**
```bash
cd /home/morgana/caldera
sudo python3 server.py
```

**Su Windows:**
- Apri Excel
- Carica Merlino
- Usa normalmente - connessione automatica

### Verifica Stato

**Da Windows PowerShell:**
```powershell
# Quick health check
Invoke-WebRequest -Uri https://192.168.124.133/nginx-health
```

## 🎉 Risultato Finale

```
┌─────────────────────────────────┐
│  Windows - Merlino (Excel)      │
│  https://...                    │
└────────────┬────────────────────┘
             │ HTTPS + CORS
             │ Header: KEY
             ▼
┌─────────────────────────────────┐
│  Ubuntu - Nginx :443            │
│  + SSL Termination              │
│  + CORS Headers                 │
└────────────┬────────────────────┘
             │ HTTP localhost
             ▼
┌─────────────────────────────────┐
│  Ubuntu - Caldera :8888         │
│  API REST                       │
└─────────────────────────────────┘
```

## 📞 Domande?

- Documentazione completa: `README_NGINX.md` su Ubuntu
- Istruzioni originali: `ngix_setup.md` su Ubuntu
- Setup manuale: `setup_nginx_proxy.sh` su Ubuntu

---

**Note:**
- IP Server Ubuntu: `192.168.124.133` (verifica sia corretto)
- Porta Nginx: `443` (HTTPS)
- Porta Caldera: `8888` (HTTP localhost)
- Certificato: `/etc/nginx/ssl/caldera.crt` su Ubuntu
