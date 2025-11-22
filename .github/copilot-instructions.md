# Copilot Instructions - Caldera Project

## Panoramica del Progetto

Questo è un fork del progetto **MITRE Caldera™** - una piattaforma di cyber security progettata per automatizzare l'emulazione degli avversari, assistere i red team manuali e automatizzare la risposta agli incidenti.

- **Repository**: x3m-ai/caldera (fork da mitre/caldera)
- **Branch**: master
- **Framework**: Python 3.12.3, aiohttp, Vue.js (Magma UI)
- **Versione Node.js**: 20.19.5

## Struttura del Progetto

### Core System
- **server.py**: Entry point principale del server C2
- **app/**: Codice principale del framework
  - `api/`: REST API endpoints
  - `contacts/`: Canali di comunicazione C2 (HTTP, DNS, TCP, WebSocket, etc.)
  - `objects/`: Oggetti core (Agent, Ability, Adversary, Operation, etc.)
  - `service/`: Servizi business logic
  - `planners/`: Logica di planning delle operazioni
  - `learning/`: Machine learning per learning automatico

### Plugins
Tutti i plugin sono gestiti come Git submodules in `plugins/`:
- **access**: Strumenti di accesso iniziale per red team
- **atomic**: TTPs del progetto Atomic Red Team
- **builder**: Compilazione dinamica dei payload
- **compass**: Visualizzazioni ATT&CK
- **debrief**: Insights sulle operazioni
- **fieldmanual**: Documentazione
- **magma**: Vue.js UI (v5)
- **manx**: Funzionalità shell e reverse shell
- **sandcat**: Agent di default
- **stockpile**: Repository di tecniche e profili
- **training**: Certificazioni e corsi

### Configurazione
- **conf/default.yml**: Configurazione principale
- **conf/agents.yml**: Configurazione degli agent
- **Virtual Environment**: `.calderavenv/`

## Setup Ambiente di Sviluppo

```bash
# Attivare l'ambiente virtuale
source .calderavenv/bin/activate

# Avviare il server (modalità insecure per sviluppo)
python3 server.py --insecure

# Accesso web UI
http://localhost:8888

# Credenziali default
# Red API Key: ADMIN123
# Blue API Key: BLUEADMIN123
```

## Features Migliorate / Modifiche

### [Data: 2025-11-22] - Setup Iniziale
- ✅ Configurato ambiente virtuale Python
- ✅ Installate tutte le dipendenze da requirements.txt
- ✅ Scaricati tutti i plugin con git submodules
- ✅ Installato Node.js 20.x per compilare Magma UI
- ✅ Compilato frontend Vue.js (plugins/magma/dist)
- ✅ Server funzionante su porta 8888

### Note Tecniche
- **Go non installato**: Alcune funzionalità di compilazione dinamica degli agent GoLang non disponibili
- **Plugin Builder**: Richiede Docker (non installato, opzionale)
- **Modalità insecure**: Per sviluppo, usa credenziali di default

## Prossime Features da Implementare

> Questa sezione verrà aggiornata con le nuove features che svilupperemo

### Priorità Alta
- [ ] TBD

### Priorità Media
- [ ] TBD

### Priorità Bassa
- [ ] TBD

## Linee Guida per lo Sviluppo

### Coding Standards
- Python: Seguire PEP 8
- Utilizzare async/await per operazioni I/O
- Logging con il modulo logging standard
- Test: pytest per unit testing

### Best Practices
1. Testare sempre in ambiente virtuale
2. Non committare credenziali o API keys
3. Documentare le modifiche in questo file
4. Mantenere compatibilità con il core upstream quando possibile
5. Utilizzare i servizi esistenti invece di duplicare logica

### API Development
- REST API: `app/api/rest_api.py`
- Endpoints documentati con aiohttp-apispec
- Autenticazione tramite API keys

### Plugin Development
- Ogni plugin è un submodule separato
- Seguire la struttura del plugin Skeleton: https://github.com/mitre/skeleton
- Registrazione in `conf/default.yml` sotto `plugins:`

## Risorse Utili

- **Documentazione ufficiale**: https://caldera.readthedocs.io
- **ATT&CK Framework**: https://attack.mitre.org
- **Tutorial video**: https://www.youtube.com/playlist?list=PLF2bj1pw7-ZvLTjIwSaTXNLN2D2yx-wXH
- **Repository upstream**: https://github.com/mitre/caldera

## Architettura Tecnica Dettagliata

### Flusso di Esecuzione
1. **Bootstrap** (`server.py`):
   - Carica configurazione da `conf/default.yml`
   - Inizializza servizi (data_svc, planning_svc, contact_svc, etc.)
   - Registra plugin come submodules Git
   - Avvia web application aiohttp
   - Compila frontend Vue.js (Magma) se necessario

2. **Servizi Core** (`app/service/`):
   - **app_svc**: Gestione lifecycle applicazione, plugin, scheduler
   - **data_svc**: Persistenza oggetti in RAM e su disco (`object_store`)
   - **planning_svc**: Generazione link, gestione buckets, esecuzione planner
   - **contact_svc**: Gestione beacon agent e decodifica comunicazioni
   - **knowledge_svc**: Knowledge base con fatti (facts) raccolti
   - **auth_svc**: Autenticazione e gestione sessioni

3. **Oggetti Core** (`app/objects/`):
   - **Agent**: Rappresenta endpoint compromesso con executors, paw, platform
   - **Ability**: Singola tecnica ATT&CK con executors per piattaforme diverse
   - **Adversary**: Collezione ordinata di abilities (atomic_ordering)
   - **Operation**: Esecuzione di adversary su agents, gestisce chain di link
   - **Planner**: Logica decisionale per ordinamento abilities
   - **Link**: Istanza di ability pronta per esecuzione su agent specifico

### Sistema dei Planners
- **Buckets**: Stati della state machine (es: initial-access, privilege-escalation, collection)
- **Atomic Planner**: Esegue abilities nell'ordine dell'adversary (atomic_ordering)
- **Bucket Planner**: Esegue abilities per bucket ATT&CK in sequenza
- `planning_svc.execute_planner()` loop: esegue bucket method → aggiorna `next_bucket` → ripete
- `exhaust_bucket()`: Applica tutti i link di un bucket fino a completamento

### Canali C2 (`app/contacts/`)
- **HTTP** (`contact_http.py`): Beacon POST su `/beacon` con heartbeat JSON
- **DNS**: Query DNS con dati codificati
- **TCP/UDP**: Socket raw per comunicazione binaria
- **WebSocket**: Comunicazione bidirezionale real-time
- Ogni contact decodifica beacon, chiama `contact_svc.handle_heartbeat()`, restituisce instructions

### Plugin System
- **Sandcat** (`plugins/sandcat/`): Agent GoLang cross-platform, compilazione dinamica
- **Stockpile** (`plugins/stockpile/`): Repository abilities YAML organizzate per tactic
- **Magma** (`plugins/magma/`): Frontend Vue.js v5, compilato con Vite
- **Manx**: Shell capabilities e reverse shell payloads
- **Atomic**: Atomic Red Team TTPs integrati

### Data Model
- **Abilities**: File YAML in `plugins/*/data/abilities/[tactic]/[uuid].yml`
  - Contengono: id, name, tactic, technique_id, executors (platform-specific)
  - Parsers per estrarre facts dall'output
- **Adversaries**: File YAML con atomic_ordering (lista di ability IDs)
- **Facts**: Triple (trait, value, score) raccolte durante operations
- **Sources**: Seed facts iniziali per operations

### REST API
- **v1** (`app/api/rest_api.py`): Endpoint `/api/rest` con routing basato su index
  - GET: display_objects, POST: updates, PUT: create, DELETE: remove
- **v2** (`app/api/v2/`): API RESTful moderna con OpenAPI docs su `/api/docs`
- Autenticazione: API keys (red/blue) in headers o cookie-based sessions

## Note per GitHub Copilot

Quando lavori su questo progetto:
- **Modello asincrono**: Tutto usa async/await con asyncio e aiohttp
- **Agents** = endpoint compromessi (beacons) con executors (sh, psh, cmd)
- **Abilities** = singole tecniche ATT&CK, multi-platform con parsers
- **Adversaries** = profili APT con sequenza ordinata di abilities
- **Operations** = esecuzioni live: adversary + agents + planner + facts
- **Planners** = AI decisionale (atomic order, buckets, ML-based)
- **Links** = abilities istanziate per agent specifico (in chain o potential_links)
- **Buckets** = raggruppamenti logici abilities (tactic o custom)
- **Facts** = conoscenza dinamica raccolta (es: host.user.name = "admin")
- Schema marshmallow per serializzazione/validazione
- RAM storage (`data_svc.ram`) + pickle persistence (`data/object_store`)
