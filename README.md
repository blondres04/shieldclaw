<p align="center">
  <h1 align="center">Shield Claw</h1>
  <p align="center"><strong>Autonomous DevSecOps Verification Agent</strong></p>
  <p align="center">
    <img src="https://img.shields.io/badge/Status-V0_Proof_of_Concept-yellow?style=flat-square" alt="Status: PoC" />
    <img src="https://img.shields.io/badge/Java-21-orange?style=flat-square&logo=openjdk" alt="Java 21" />
    <img src="https://img.shields.io/badge/Spring_Boot-3.4-6DB33F?style=flat-square&logo=springboot&logoColor=white" alt="Spring Boot 3.4" />
    <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React 19" />
    <img src="https://img.shields.io/badge/Kafka-3.8-231F20?style=flat-square&logo=apachekafka&logoColor=white" alt="Kafka 3.8" />
    <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL 16" />
    <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
    <img src="https://img.shields.io/badge/Ollama-gemma3:12b-purple?style=flat-square" alt="Ollama" />
    <img src="https://img.shields.io/badge/PyTest-Passing-green?style=flat-square&logo=pytest&logoColor=white" alt="PyTest" />
  </p>
</p>

---

## What Is Shield Claw?

Shield Claw is an open-source DevSecOps pipeline that **empirically verifies** LLM-generated security vulnerabilities instead of trusting static analysis.

Most AI security tools analyze code and flag patterns that *might* be vulnerable. The result is a high volume of false positives — hallucinated vulnerabilities that waste engineering hours. Shield Claw takes a different approach: it uses a local LLM to generate an exploit from a code change, then **autonomously detonates that exploit in an ephemeral Docker sandbox** and only alerts engineers if the vulnerability is proven to be real.

The pipeline is fully containerized and launches with a single `docker compose` command. It spans a Python red-team agent, an Apache Kafka event backbone, a Spring Boot backend with JWT-authenticated audit workflows, a PostgreSQL persistence layer, and a React telemetry dashboard.

<!-- [Demo Video Coming Soon] -->

---

## How It Works

Shield Claw operates as a closed-loop verification pipeline:

1. **Hypothesize** — A Python agent powered by a local LLM (Ollama/Gemma 3) generates a theoretical exploit payload targeting OWASP Top 10 vulnerability classes.
2. **Detonate** — A sandbox orchestrator spins up an ephemeral Docker container, clones the target repository, and executes the payload in isolation.
3. **Verify** — The system records whether the exploit succeeded or failed based on empirical execution results (exit codes, stdout/stderr). Payloads that fail execution are tagged `empiricallyVerified: false` before reaching the database.
4. **Ingest** — Verified payloads flow through an Apache Kafka event backbone into a Spring Boot backend that persists them in PostgreSQL.
5. **Audit** — A JWT-authenticated React dashboard presents security engineers with a side-by-side diff viewer, an OWASP-categorized approval/rejection workflow, and real-time telemetry tracking verified vs. failed exploits.

---

## Current Limitations

Shield Claw is a **V0 proof of concept** in active development. Transparency about its constraints:

- **False-Negative Tradeoff:** The V0 sandbox detonates payloads in a bare Alpine container. This successfully verifies OS-level command injections and logic flaws but yields **false negatives** for application-layer vulnerabilities (SQLi, XSS, SSRF) that require a running HTTP server or database. Upgrading to a Docker-Compose-aware sandbox that boots the full target application stack is the next milestone.
- **Single-Shot Payloads:** The agent generates single bash-script exploits. Multi-step, stateful attack chains are not yet supported.
- **Network Access:** Sandbox containers require outbound network access to clone the target repository via `git clone`. They are ephemeral and destroyed after each run, but they are not fully network-restricted. Transitioning to a `docker cp` injection model to eliminate outbound access is on the roadmap.
- **Sibling Containers, Not True DinD:** The sandbox orchestrator mounts the host Docker socket (`/var/run/docker.sock`). Sandbox containers run as sibling containers on the host daemon, not as nested Docker-in-Docker. This is a known privilege escalation surface documented in [SECURITY.md](./SECURITY.md).

---

## Quick Start

### Prerequisites

| Dependency | Purpose |
|---|---|
| **Docker** and **Docker Compose** | Runs the entire platform (all five services) |
| **Ollama** (on host machine) | Local LLM inference for the Red Team Agent |

Pull the required model before launching:

```bash
ollama pull gemma3:12b
```

### Launch

```bash
git clone <repo-url> && cd shield-claw
cp red-team-agent/.env.example red-team-agent/.env
# Edit .env with your GitHub PAT and target repo settings
docker compose up --build -d
```

Docker Compose builds and starts all five services:

| Service | Container | Port | Description |
|---|---|---|---|
| **PostgreSQL 16** | `shieldclaw-postgres` | `5432` | Persistent audit database |
| **Apache Kafka 3.8** | `shieldclaw-kafka` | `9092` | Event backbone (KRaft, no ZooKeeper) |
| **Spring Boot Backend** | `shieldclaw-backend` | `8080` | REST API, Kafka consumers, JWT auth |
| **React Frontend** | `shieldclaw-frontend` | `5173` | Audit dashboard (nginx) |
| **Red Team Agent** | `shieldclaw-red-team` | — | Exploit generation and sandbox verification |

Open **http://localhost:5173** and sign in.

### Default Credentials

> **Username:** `auditor`  
> **Password:** `secure2026`

⚠️ **These are development defaults.** Change them before any non-local deployment. The server issues an 8-hour HttpOnly JWT cookie upon authentication.

### Verify the Pipeline

```bash
docker compose logs -f red-team-agent
```

You should see the agent generating and verifying payloads every 15 seconds. Verified results appear in the dashboard within moments.

### Tear Down

```bash
docker compose down -v
```

---

## Architecture

```
┌──────────────────────┐       shared volume      ┌────────────────────────────────────────┐
│  Python / Ollama     │  ──── /app/payloads ───▶  │  Spring Boot 3.4 Backend (:8080)       │
│  Red Team Agent      │   (ai-generated-*.json)   │                                        │
│  gemma3:12b          │   temp/ → ready/ atomic   │  ┌─────────────┐    Kafka topic         │
│  (continuous loop)   │                           │  │  Ingestion   │──audit.pr.ingested──▶ │
│                      │                           │  │  @Scheduled  │                       │
│  Sandbox Orchestrator│                           │  └─────────────┘    ┌──────────────┐   │
│  (ephemeral Alpine   │                           │                     │  Audit        │   │
│   containers via     │                           │                ◀────│  @KafkaListener│  │
│   host Docker socket)│                           │                     └──────┬───────┘   │
└──────────────────────┘                           │                            │ JPA       │
                                                   │                     ┌──────▼───────┐   │
                                                   │                     │  PostgreSQL   │   │
                                                   │                     │  shieldclaw_db│   │
                                                   │                     └──────┬───────┘   │
                                                   │  ┌─────────────┐   ┌──────▼───────┐   │
                                                   │  │ Telemetry   │◀──│  Audit REST  │   │
                                                   │  │ GET /stats  │   │  GET/POST    │   │
                                                   │  └──────┬──────┘   └──────┬───────┘   │
                                                   │         │    Security     │            │
                                                   │         │  ┌─────────────┐│            │
                                                   │         │  │ JWT Filter  ││            │
                                                   │         │  │ HttpOnly    ││            │
                                                   │         │  └──────┬──────┘│            │
                                                   └─────────┼─────────┼───────┼────────────┘
                                                             │         │       │
                                                        GET /stats  Cookie   GET & POST
                                                             │   HttpOnly    │
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
                                                   │  │  Sandbox Verification Metrics      │  │
                                                   │  └────────────────────────────────────┘  │
                                                   └──────────────────────────────────────────┘
```

### 1. Red Team Agent (`red-team-agent/`)

Standalone Python process running in a continuous `while True` loop with 15-second intervals. Each cycle: targets an OWASP Top 10 category (A01–A10), prompts `gemma3:12b` via Ollama with `format="json"`, defensively strips markdown fences and conversational preamble, validates the output through Pydantic schema enforcement, and executes the payload in an ephemeral Alpine sandbox via the Docker SDK. The result is written atomically (write to `temp/`, then `os.rename` to `ready/`) to the shared Docker volume. Errors are caught per-cycle — the loop never crashes.

### 2. Sandbox Orchestrator (`red-team-agent/sandbox_orchestrator.py`)

Uses the Docker SDK to spin up ephemeral Alpine containers via the host Docker socket. Each container installs git, clones the target repository, navigates into the workspace, and executes the generated payload. Containers are memory-limited (128MB), auto-removed on completion, and success/failure is determined by exit code. Payloads that fail execution (non-zero exit, missing dependencies, hallucinated file paths) are tagged `empiricallyVerified: false`, filtering out LLM hallucinations before they reach human reviewers.

### 3. Spring Boot Backend (root Java application)

Spring Boot 3.4 application with four bounded contexts:

- **Security** — Stateless JWT authentication via Spring Security. A `JwtAuthenticationFilter` intercepts every request, extracts the JWT from an HttpOnly cookie, validates it, and sets the `SecurityContext`. CSRF is disabled; sessions are `STATELESS`. Login is public; all audit and telemetry endpoints require authentication.
- **Ingestion** — A `@Scheduled` task scans the shared payload volume's `ready/` subdirectory every 15 seconds, deserializes JSON files, publishes them to the `audit.pr.ingested` Kafka topic with the PR ID as the message key, and deletes the file after successful publish.
- **Audit** — A `@KafkaListener` consumes from the topic, persists `PullRequestEntity` records with `PENDING_AUDIT` status, and exposes REST endpoints for fetching pending PRs and recording audit decisions. The `SKIP LOCKED` checkout pattern ensures no two auditors receive the same PR. Scoring logic: approving a poisoned PR = `AUDIT_FAILED_MISSED_THREAT`; rejecting a clean PR = `AUDIT_FAILED_FALSE_POSITIVE`; correct decisions = `AUDIT_PASSED`.
- **Telemetry** — Native PostgreSQL `json_object_agg` + `GROUP BY` aggregation query on audit statuses and empirical verification flags, served via `GET /api/v1/audit/stats`.

### 4. React Dashboard (`frontend/`)

Vite-powered React 19 SPA served by nginx in production. A JWT login gateway blocks all access until the auditor authenticates. Every API call includes `credentials: "include"` to transmit the HttpOnly cookie. The dashboard renders a split-pane code diff viewer (original vs. exploit), an empirical verification badge (sandbox pass/fail), a blind audit action panel (OWASP category selection + approve/reject), and a Recharts donut chart for real-time telemetry with sandbox verification metric cards.

---

## Security Architecture

Shield Claw implements a stateless JWT security layer across the full stack:

**Backend (Spring Security)**
- `POST /api/v1/auth/login` accepts `{ username, password }` and sets a signed JWT in an HttpOnly cookie
- Tokens are HS256-signed with an 8-hour expiry
- `JwtAuthenticationFilter` (a `OncePerRequestFilter`) extracts and validates the JWT from the request cookie on every request
- `SecurityFilterChain` enforces: login and logout are public; all `/api/v1/audit/**` endpoints require authentication
- CSRF is disabled (stateless API); sessions are set to `STATELESS`
- CORS is configured with `allowCredentials: true` to permit cookie transmission from the frontend origin

**Frontend (React)**
- `App.tsx` acts as an auth gateway: on mount, calls `GET /api/v1/auth/me` — if 200, render `<AuditDashboard />`; otherwise, render `<Login />`
- Every `fetch` call includes `credentials: "include"` to transmit the HttpOnly cookie
- Any 401 or 403 response triggers automatic redirect to login
- Logout calls `POST /api/v1/auth/logout` which clears the cookie server-side

---

## Chaos Engineering and Testing

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

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | Public | Authenticate and receive JWT cookie |
| `POST` | `/api/v1/auth/logout` | Public | Clear JWT cookie |
| `GET` | `/api/v1/auth/me` | Cookie | Verify session validity |
| `GET` | `/api/v1/audit/pending` | Cookie | Fetch next pending PR for review (`SKIP LOCKED`) |
| `POST` | `/api/v1/audit/{prId}/evaluate` | Cookie | Submit audit decision (approve/reject) |
| `GET` | `/api/v1/audit/stats` | Cookie | Aggregate audit status counts and verification metrics |

---

## Roadmap

Shield Claw is being developed iteratively. Contributions and architectural feedback are welcome.

- [ ] **Dynamic Sandboxing** — Upgrade the orchestrator to parse target `docker-compose.yml` files and boot the full application stack (web server, database) inside the sandbox before detonation, enabling application-layer exploit verification.
- [ ] **Ground-Truth Validation** — Benchmark the pipeline against a held-out dataset of intentionally vulnerable PRs to publish a verified detection rate using a training/evaluation split methodology.
- [ ] **PR-Driven Reconnaissance** — Upgrade the agent to monitor live GitHub PRs and analyze real code diffs rather than generating synthetic payloads.
- [ ] **Cloud-Native Deployment** — Port the local Docker Compose architecture into Terraform scripts for AWS ECS/EKS.
- [ ] **Automated Remediation** — If an exploit is empirically verified, generate and commit a patch PR to fix the vulnerability.

---

## Technical Stack

**Backend:** Java 21, Spring Boot 3.4.4, Spring Security (stateless JWT, HttpOnly cookies), JJWT 0.11.5, Apache Kafka 3.8 (KRaft), PostgreSQL 16, Hibernate ORM, Lombok, Maven

**Frontend:** React 19, TypeScript 5.9, Vite 8, react-diff-viewer-continued 4.x, Recharts 3.x, nginx

**Red Team Agent:** Python 3.10+, Ollama, Gemma 3 12B, Docker SDK, Pydantic, PyTest

**Infrastructure:** Docker Compose (5 services, 2 named volumes), multi-stage Dockerfiles, shared volume with atomic move pattern

---

## Project Structure

```
shield-claw/
├── docker-compose.yml              # Full-stack orchestration (5 services)
├── Dockerfile                       # Spring Boot multi-stage build
├── pom.xml                          # Maven dependencies
├── src/main/java/com/shieldclaw/
│   ├── ShieldClawApplication.java   # Entry point (@EnableScheduling)
│   ├── security/                    # JWT auth layer
│   │   ├── AuthController.java      # POST /login, /logout, GET /me
│   │   ├── JwtService.java          # Token generation and validation
│   │   ├── JwtAuthenticationFilter  # HttpOnly cookie extraction filter
│   │   └── SecurityConfig.java      # SecurityFilterChain
│   ├── ingestion/                   # File → Kafka pipeline
│   │   ├── OfflinePayloadIngester   # @Scheduled file scanner (ready/)
│   │   └── KafkaProducerService     # Topic publisher (PR ID keyed)
│   ├── audit/                       # Core audit domain
│   │   ├── AuditController.java     # REST endpoints
│   │   ├── AuditService.java        # SKIP LOCKED checkout + scoring
│   │   ├── KafkaConsumerService     # Topic listener → JPA persist
│   │   └── PullRequestEntity.java   # JPA entity
│   └── telemetry/                   # Metrics domain
│       ├── TelemetryController.java # GET /audit/stats
│       └── TelemetryService.java    # Native SQL aggregation
├── frontend/
│   ├── Dockerfile                   # Node → nginx multi-stage
│   └── src/
│       ├── App.tsx                  # Auth gateway
│       ├── components/
│       │   ├── Login.tsx            # JWT login form
│       │   ├── AuditDashboard.tsx   # Diff viewer + audit panel
│       │   └── TelemetryChart.tsx   # Donut chart + verification cards
│       └── types/Audit.ts          # Shared TypeScript interfaces
└── red-team-agent/
    ├── Dockerfile                   # Python slim image
    ├── agent.py                     # LLM payload generator + sandbox orchestration
    ├── sandbox_orchestrator.py      # Docker SDK ephemeral container management
    ├── github_recon.py              # PyGithub PR diff extraction
    ├── test_agent.py                # PyTest chaos test suite
    └── requirements.txt             # ollama, pydantic, docker, pytest
```

---

## Contributing

Architectural feedback, bug reports, and PRs are welcome. If you're interested in contributing to the dynamic sandboxing layer or building out the validation test suite, please open an issue.

## Responsible Use

Shield Claw is a defensive security research tool. You may only run it against repositories and infrastructure you own or have explicit permission to test. See [RESPONSIBLE_USE.md](./RESPONSIBLE_USE.md) for the full policy.

## License

Apache 2.0 — See [LICENSE](./LICENSE)
