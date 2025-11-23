# Copilot Instructions - Caldera Project

## Project Overview

This is a fork of the **MITRE Caldera™** project - a cyber security platform designed to automate adversary emulation, assist manual red teams, and automate incident response.

- **Repository**: x3m-ai/caldera (fork from mitre/caldera)
- **Branch**: master
- **Framework**: Python 3.12.3, aiohttp, Vue.js (Magma UI)
- **Node.js Version**: 20.19.5

## Project Structure

### Core System
- **server.py**: Main C2 server entry point
- **app/**: Core framework code
  - `api/`: REST API endpoints
  - `contacts/`: C2 communication channels (HTTP, DNS, TCP, WebSocket, etc.)
  - `objects/`: Core objects (Agent, Ability, Adversary, Operation, etc.)
  - `service/`: Business logic services
  - `planners/`: Operation planning logic
  - `learning/`: Machine learning for automated learning

### Plugins
All plugins are managed as Git submodules in `plugins/`:
- **access**: Initial access tools for red teams
- **atomic**: Atomic Red Team project TTPs
- **builder**: Dynamic payload compilation
- **compass**: ATT&CK visualizations
- **debrief**: Operation insights
- **fieldmanual**: Documentation
- **magma**: Vue.js UI (v5)
- **manx**: Shell and reverse shell functionality
- **sandcat**: Default agent
- **stockpile**: Repository of techniques and profiles
- **training**: Certifications and courses

### Configuration
- **conf/default.yml**: Main configuration
- **conf/agents.yml**: Agent configuration
- **Virtual Environment**: `.calderavenv/`

## Development Environment Setup

```bash
# Activate virtual environment
source .calderavenv/bin/activate

# Start server in background (recommended for development)
# This allows you to continue working in the terminal
nohup python3 server.py --insecure > caldera.log 2>&1 &

# Monitor server logs in real-time
tail -f caldera.log

# Stop the server when needed
pkill -f "python3 server.py"

# Web UI access
http://localhost:8888

# Default credentials
# Red API Key: ADMIN123
# Blue API Key: BLUEADMIN123
```

## Implemented Features / Changes

### [Date: 2025-11-22] - Initial Setup
- ✅ Configured Python virtual environment
- ✅ Installed all dependencies from requirements.txt
- ✅ Downloaded all plugins with git submodules
- ✅ Installed Node.js 20.x to compile Magma UI
- ✅ Compiled Vue.js frontend (plugins/magma/dist)
- ✅ Server running on port 8888

### [Date: 2025-11-23] - CORS Support for Web Clients
- ✅ Implemented global CORS middleware for cross-origin requests
- ✅ Added CORS configuration to `conf/default.yml` (enabled flag and allowed_origins)
- ✅ Configured middleware to handle OPTIONS preflight requests automatically
- ✅ Tested with curl: verified CORS headers on both OPTIONS and GET requests
- **Purpose**: Enable direct API access from Merlino Excel Add-in (https://merlino-addin.x3m.ai)
- **Impact**: Eliminates need for Python proxy server (port 8889 workaround)
- **Configuration**:
  ```yaml
  cors:
    enabled: true
    allowed_origins: "*"  # Safe for local network VM deployment
  ```
- **Headers Applied**: Access-Control-Allow-Origin, Allow-Methods, Allow-Headers, Allow-Credentials, Max-Age
- **Authentication**: Caldera API key passed via `KEY` header (e.g., `KEY: ADMIN123`)

### Technical Notes
- **Go not installed**: Some GoLang agent dynamic compilation features unavailable
- **Builder Plugin**: Requires Docker (not installed, optional)
- **Insecure mode**: For development, uses default credentials

## Upcoming Features to Implement

> This section will be updated with new features as we develop them

### High Priority
- [ ] TBD

### Medium Priority
- [ ] TBD

### Low Priority
- [ ] TBD

## Development Guidelines

### Coding Standards
- Python: Follow PEP 8
- Use async/await for I/O operations
- Logging with standard logging module
- Testing: pytest for unit testing

### Best Practices
1. Always test in virtual environment
2. Never commit credentials or API keys
3. Document changes in this file
4. Maintain compatibility with upstream core when possible
5. Use existing services instead of duplicating logic

### API Development
- REST API: `app/api/rest_api.py`
- Endpoints documented with aiohttp-apispec
- Authentication via API keys

### Plugin Development
- Each plugin is a separate submodule
- Follow Skeleton plugin structure: https://github.com/mitre/skeleton
- Registration in `conf/default.yml` under `plugins:`

## Useful Resources

- **Official Documentation**: https://caldera.readthedocs.io
- **ATT&CK Framework**: https://attack.mitre.org
- **Video Tutorials**: https://www.youtube.com/playlist?list=PLF2bj1pw7-ZvLTjIwSaTXNLN2D2yx-wXH
- **Upstream Repository**: https://github.com/mitre/caldera

## Detailed Technical Architecture

### Execution Flow
1. **Bootstrap** (`server.py`):
   - Load configuration from `conf/default.yml`
   - Initialize services (data_svc, planning_svc, contact_svc, etc.)
   - Register plugins as Git submodules
   - Start aiohttp web application
   - Compile Vue.js frontend (Magma) if needed

2. **Core Services** (`app/service/`):
   - **app_svc**: Application lifecycle management, plugins, scheduler
   - **data_svc**: Object persistence in RAM and disk (`object_store`)
   - **planning_svc**: Link generation, bucket management, planner execution
   - **contact_svc**: Agent beacon management and communication decoding
   - **knowledge_svc**: Knowledge base with collected facts
   - **auth_svc**: Authentication and session management

3. **Core Objects** (`app/objects/`):
   - **Agent**: Represents compromised endpoint with executors, paw, platform
   - **Ability**: Single ATT&CK technique with executors for different platforms
   - **Adversary**: Ordered collection of abilities (atomic_ordering)
   - **Operation**: Execution of adversary on agents, manages link chain
   - **Planner**: Decision logic for ability ordering
   - **Link**: Ability instance ready for execution on specific agent

### Planner System
- **Buckets**: State machine states (e.g., initial-access, privilege-escalation, collection)
- **Atomic Planner**: Executes abilities in adversary order (atomic_ordering)
- **Bucket Planner**: Executes abilities by ATT&CK bucket in sequence
- `planning_svc.execute_planner()` loop: execute bucket method → update `next_bucket` → repeat
- `exhaust_bucket()`: Apply all links from a bucket until completion

### C2 Channels (`app/contacts/`)
- **HTTP** (`contact_http.py`): Beacon POST to `/beacon` with JSON heartbeat
- **DNS**: DNS queries with encoded data
- **TCP/UDP**: Raw sockets for binary communication
- **WebSocket**: Bidirectional real-time communication
- Each contact decodes beacon, calls `contact_svc.handle_heartbeat()`, returns instructions

### Plugin System
- **Sandcat** (`plugins/sandcat/`): Cross-platform GoLang agent, dynamic compilation
- **Stockpile** (`plugins/stockpile/`): YAML abilities repository organized by tactic
- **Magma** (`plugins/magma/`): Vue.js v5 frontend, compiled with Vite
- **Manx**: Shell capabilities and reverse shell payloads
- **Atomic**: Integrated Atomic Red Team TTPs

### Data Model
- **Abilities**: YAML files in `plugins/*/data/abilities/[tactic]/[uuid].yml`
  - Contain: id, name, tactic, technique_id, executors (platform-specific)
  - Parsers to extract facts from output
- **Adversaries**: YAML files with atomic_ordering (list of ability IDs)
- **Facts**: Triples (trait, value, score) collected during operations
- **Sources**: Initial seed facts for operations

### REST API
- **v1** (`app/api/rest_api.py`): `/api/rest` endpoint with index-based routing
  - GET: display_objects, POST: updates, PUT: create, DELETE: remove
- **v2** (`app/api/v2/`): Modern RESTful API with OpenAPI docs at `/api/docs`
- Authentication: API keys (red/blue) in headers or cookie-based sessions

## Notes for GitHub Copilot

When working on this project:
- **Async model**: Everything uses async/await with asyncio and aiohttp
- **Agents** = compromised endpoints (beacons) with executors (sh, psh, cmd)
- **Abilities** = single ATT&CK techniques, multi-platform with parsers
- **Adversaries** = APT profiles with ordered sequence of abilities
- **Operations** = live executions: adversary + agents + planner + facts
- **Planners** = decision AI (atomic order, buckets, ML-based)
- **Links** = abilities instantiated for specific agent (in chain or potential_links)
- **Buckets** = logical ability groupings (tactic or custom)
- **Facts** = dynamic knowledge collected (e.g., host.user.name = "admin")
- Marshmallow schemas for serialization/validation
- RAM storage (`data_svc.ram`) + pickle persistence (`data/object_store`)
