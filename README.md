<p align="center">
  <h1 align="center">Aegis Gate</h1>
  <p align="center"><strong>AI-Driven DevSecOps Audit Platform</strong></p>
  <p align="center">
    <img src="https://img.shields.io/badge/Java-21-orange?style=flat-square&logo=openjdk" alt="Java 21" />
    <img src="https://img.shields.io/badge/Spring_Boot-3.4-6DB33F?style=flat-square&logo=springboot&logoColor=white" alt="Spring Boot 3.4" />
    <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React 19" />
    <img src="https://img.shields.io/badge/Kafka-3.8-231F20?style=flat-square&logo=apachekafka&logoColor=white" alt="Kafka 3.8" />
    <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL 16" />
    <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
    <img src="https://img.shields.io/badge/JWT-HS256-000000?style=flat-square&logo=jsonwebtokens&logoColor=white" alt="JWT" />
    <img src="https://img.shields.io/badge/Ollama-gemma3:12b-purple?style=flat-square" alt="Ollama" />
    <img src="https://img.shields.io/badge/PyTest-Passing-green?style=flat-square&logo=pytest&logoColor=white" alt="PyTest" />
  </p>
</p>

---

## Executive Summary

Aegis Gate is a full-stack DevSecOps audit platform that closes the loop between adversarial AI payload generation, asynchronous event-driven ingestion, JWT-authenticated human-in-the-loop blind code review, and real-time telemetry. An air-gapped Python agent powered by a local Ollama LLM (`gemma3:12b`) runs in a continuous loop, autonomously generating poisoned Java Spring Boot pull request payloads targeting OWASP Top 10 vulnerability categories. These payloads flow through an Apache Kafka message backbone into a Spring Boot backend that persists them in PostgreSQL for human audit. A React dashboard — protected by a stateless JWT authentication gateway — presents security engineers with a side-by-side diff viewer for original vs. poisoned code snippets, an OWASP-categorized approval/rejection workflow, and a live donut chart tracking audit pass/fail telemetry. The entire stack is containerized and launches with a single `docker compose` command.

---

## Quick Start Guide

### Prerequisites

| Dependency | Purpose |
|---|---|
| **Docker** & **Docker Compose** | Runs the entire platform (all five services) |
| **Ollama** (on host machine) | Local LLM inference for the Red Team Agent |

Pull the required model before launching:

```bash
ollama pull gemma3:12b
```

### One-Click Launch

```bash
git clone <repo-url> && cd aegis-gate
docker compose up --build -d
```

That's it. Docker Compose builds and starts all five services:

| Service | Container | Port | Description |
|---|---|---|---|
| **PostgreSQL 16** | `aegis-postgres` | `5432` | Persistent audit database |
| **Apache Kafka 3.8** | `aegis-kafka` | `9092` | Event backbone (KRaft, no ZooKeeper) |
| **Spring Boot Backend** | `aegis-backend` | `8080` | REST API, Kafka consumers, JWT auth |
| **React Frontend** | `aegis-frontend` | `5173` | Audit dashboard (nginx) |
| **Red Team Agent** | `aegis-red-team` | — | Continuous adversarial payload generator |

Open **http://localhost:5173** and sign in.

### Default Credentials

> **Username:** `auditor`
> **Password:** `secure2026`

These credentials are required to pass the JWT login gateway. Upon successful authentication, the dashboard issues an 8-hour Bearer token stored in `localStorage`.

### Verify the Pipeline

```bash
docker compose logs -f red-team-agent
```

You should see the agent generating payloads every 15 seconds. They appear in the dashboard within moments.

### Tear Down

```bash
docker compose down -v
```

---

## High-Level Architecture

```
┌──────────────────────┐       shared volume      ┌────────────────────────────────────────┐
│  Python / Ollama     │  ──── /app/payloads ───▶  │  Spring Boot 3.4 Backend (:8080)       │
│  Red Team Agent      │   (ai-generated-*.json)   │                                        │
│  gemma3:12b          │                           │  ┌─────────────┐    Kafka topic         │
│  (continuous loop)   │                           │  │  Ingestion   │──audit.pr.ingested──▶ │
└──────────────────────┘                           │  │  @Scheduled  │                       │
                                                   │  └─────────────┘    ┌──────────────┐   │
                                                   │                     │  Audit        │   │
                                                   │                ◀────│  @KafkaListener│  │
                                                   │                     └──────┬───────┘   │
                                                   │                            │ JPA       │
                                                   │                     ┌──────▼───────┐   │
                                                   │                     │  PostgreSQL   │   │
                                                   │                     │  aegis_db     │   │
                                                   │                     └──────┬───────┘   │
                                                   │  ┌─────────────┐   ┌──────▼───────┐   │
                                                   │  │ Telemetry   │◀──│  Audit REST  │   │
                                                   │  │ GET /stats  │   │  GET/POST    │   │
                                                   │  └──────┬──────┘   └──────┬───────┘   │
                                                   │         │    Security     │            │
                                                   │         │  ┌─────────────┐│            │
                                                   │         │  │ JWT Filter  ││            │
                                                   │         │  │ HS256/8hr   ││            │
                                                   │         │  └──────┬──────┘│            │
                                                   └─────────┼─────────┼───────┼────────────┘
                                                             │         │       │
                                                        GET /stats  Auth   GET & POST
                                                             │    Bearer     │
                                                   ┌─────────▼─────────▼─────▼───────────────┐
                                                   │  React 19 Dashboard (:5173 → nginx)      │
                                                   │                                          │
                                                   │  ┌────────────────────────────────────┐  │
                                                   │  │  JWT Login Gateway                 │  │
                                                   │  ├────────────────────────────────────┤  │
                                                   │  │  Code Diff Viewer (split pane)     │  │
                                                   │  ├────────────────────────────────────┤  │
                                                   │  │  Blind Audit Action Panel          │  │
                                                   │  │  (OWASP dropdown + approve/reject) │  │
                                                   │  ├────────────────────────────────────┤  │
                                                   │  │  Telemetry Donut Chart             │  │
                                                   │  └────────────────────────────────────┘  │
                                                   └──────────────────────────────────────────┘
```

### 1. React UI (`frontend/`)

Vite-powered React 19 SPA served by nginx in production. A JWT login gateway blocks all access until the auditor authenticates. Every API call includes an `Authorization: Bearer` header. If the backend returns 401/403, the token is cleared and the user is redirected to login. The dashboard renders a split-pane code diff, a blind audit action panel (threat category is deliberately hidden from the auditor), and a Recharts donut chart for real-time telemetry.

### 2. Spring Boot Kafka Backbone (root Java application)

Spring Boot 3.4 application with four bounded contexts:

- **Security** — Stateless JWT authentication via Spring Security. A `JwtAuthenticationFilter` intercepts every request, validates the Bearer token, and sets the `SecurityContext`. CSRF is disabled; sessions are `STATELESS`. The `/api/v1/auth/login` endpoint is public; all audit and telemetry endpoints require authentication.
- **Ingestion** — A `@Scheduled` task scans the shared payload volume every 15 seconds, deserializes JSON files, and publishes them to the `audit.pr.ingested` Kafka topic.
- **Audit** — A `@KafkaListener` consumes from the topic, persists `PullRequestEntity` records with `PENDING_AUDIT` status, and exposes REST endpoints for fetching pending PRs and recording audit decisions. The scoring logic: approving a poisoned PR = `AUDIT_FAILED_MISSED_THREAT`; rejecting a clean PR = `AUDIT_FAILED_FALSE_POSITIVE`; correct decisions = `AUDIT_PASSED`.
- **Telemetry** — Aggregate `GROUP BY` query on audit statuses, returned via `GET /api/v1/telemetry/stats`.

### 3. Air-Gapped Red Team Agent (`red-team-agent/`)

Standalone Python process running in a continuous `while True` loop with 15-second sleep intervals. Each cycle: randomly selects an OWASP Top 10 category (A01–A10), prompts `gemma3:12b` via Ollama with `format="json"`, defensively strips markdown fences and conversational preamble, validates the output through Pydantic schema enforcement, and writes the payload to the shared Docker volume. Errors are caught per-cycle — the loop never crashes.

---

## Security Architecture

Aegis Gate implements a stateless JWT security layer across the full stack:

**Backend (Spring Security)**
- `POST /api/v1/auth/login` accepts `{ username, password }` and returns a signed JWT
- Tokens are HS256-signed with an 8-hour expiry
- `JwtAuthenticationFilter` (a `OncePerRequestFilter`) extracts and validates the Bearer token on every request
- `SecurityFilterChain` enforces: login is public, all `/api/v1/audit/**` and `/api/v1/telemetry/**` endpoints require authentication
- CSRF is disabled (stateless API); sessions are set to `STATELESS`
- CORS is centrally configured to allow `Authorization` and `Content-Type` headers

**Frontend (React)**
- `App.tsx` acts as an auth gateway: no token in `localStorage` → render `<Login />`; valid token → render `<AuditDashboard />`
- Every `fetch` call includes `Authorization: Bearer ${token}` in its headers
- Any 401 or 403 response triggers automatic token eviction and redirect to login
- A Logout button in the top navigation clears the token and resets application state

---

## Chaos Engineering & Testing

The Red Team Agent's LLM parsing layer is backed by a deterministic PyTest suite that validates the defensive cleaning logic without any live Ollama calls.

### Running the Test Suite

```bash
cd red-team-agent
pip install -r requirements.txt
pytest -v
```

### Test Coverage

| Test | Chaos Scenario | Assertion |
|---|---|---|
| `test_clean_valid_json` | Perfect JSON string | Parses correctly into matching dict |
| `test_clean_markdown_json` | JSON wrapped in `` ```json ``` `` fences | Regex strips markdown, dict matches |
| `test_clean_conversational_json` | `"Here is your payload: \n {...}"` | Extracts JSON from conversational preamble |
| `test_clean_raises_on_garbage` | Completely unparseable text | Raises `json.JSONDecodeError` |
| `test_pydantic_validation_failure` | Dict missing `threatCategory` key | Raises Pydantic `ValidationError` |
| `test_pydantic_validation_success` | Complete well-formed dict | `PRPayload` model hydrates correctly |

The test suite proves that regardless of how the LLM formats its output — clean JSON, markdown-wrapped, or preceded by conversational text — the parsing pipeline deterministically extracts valid payloads or fails safely.

---

## Technical Stack

**Backend**
- Java 21
- Spring Boot 3.4.4 (Web, Data JPA, Kafka, Security)
- Spring Security (stateless JWT)
- JJWT 0.11.5 (HS256 token signing)
- Apache Kafka 3.8 (KRaft single-node)
- PostgreSQL 16
- Hibernate ORM (auto-DDL)
- Lombok
- Maven

**Frontend**
- React 19
- TypeScript 5.9
- Vite 8
- react-diff-viewer-continued 4.x (split-pane code diffs)
- Recharts 3.x (telemetry donut chart)
- React Compiler (via Babel plugin)
- nginx (production serving)

**Red Team Agent**
- Python 3.10+
- Ollama (local LLM inference)
- gemma3:12b model
- Pydantic (schema validation)
- PyTest + pytest-mock (chaos test suite)

**Infrastructure**
- Docker Compose (5 services, 2 named volumes)
- Multi-stage Dockerfiles (Maven, Node, Python)
- PostgreSQL 16 (persistent volume)
- Apache Kafka 3.8 (KRaft, no ZooKeeper)
- Shared Docker volume for agent-to-backend payload transfer
- `.dockerignore` files preventing OS binary conflicts

---

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | Public | Authenticate and receive JWT |
| `GET` | `/api/v1/audit/pending` | Bearer | Fetch next pending PR for review |
| `POST` | `/api/v1/audit/{prId}/evaluate` | Bearer | Submit audit decision |
| `GET` | `/api/v1/telemetry/stats` | Bearer | Aggregate audit status counts |

---

## Project Structure

```
aegis-gate/
├── docker-compose.yml              # Full-stack orchestration
├── Dockerfile                       # Spring Boot multi-stage build
├── pom.xml                          # Maven dependencies
├── src/main/java/com/aegisgate/
│   ├── AegisGateApplication.java    # Entry point (@EnableScheduling)
│   ├── security/                    # JWT auth layer
│   │   ├── AuthController.java      # POST /login
│   │   ├── JwtService.java          # Token generation & validation
│   │   ├── JwtAuthenticationFilter  # Bearer token filter
│   │   └── SecurityConfig.java      # SecurityFilterChain
│   ├── ingestion/                   # File → Kafka pipeline
│   │   ├── OfflinePayloadIngester   # @Scheduled file scanner
│   │   └── KafkaProducerService     # Topic publisher
│   ├── audit/                       # Core audit domain
│   │   ├── AuditController.java     # REST endpoints
│   │   ├── AuditService.java        # Scoring logic
│   │   ├── KafkaConsumerService     # Topic listener
│   │   └── PullRequestEntity.java   # JPA entity
│   └── telemetry/                   # Metrics domain
│       ├── TelemetryController.java # GET /stats
│       └── TelemetryService.java    # Aggregate query
├── frontend/
│   ├── Dockerfile                   # Node → nginx multi-stage
│   └── src/
│       ├── App.tsx                  # Auth gateway + routing
│       ├── components/
│       │   ├── Login.tsx            # JWT login form
│       │   ├── AuditDashboard.tsx   # Diff viewer + action panel
│       │   └── TelemetryChart.tsx   # Recharts donut chart
│       └── types/Audit.ts          # Shared TypeScript interfaces
└── red-team-agent/
    ├── Dockerfile                   # Python slim image
    ├── agent.py                     # Continuous LLM payload generator
    ├── test_agent.py                # PyTest chaos test suite
    └── requirements.txt             # ollama, pydantic, pytest
```
