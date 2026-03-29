# Aegis Gate

**AI-Driven DevSecOps Audit Platform**

---

## Executive Summary

Aegis Gate is a full-stack DevSecOps audit platform that closes the loop between adversarial AI payload generation, asynchronous event-driven ingestion, human-in-the-loop blind code review, and real-time telemetry. An air-gapped Python agent powered by a local Ollama LLM (`gemma3:12b`) autonomously generates poisoned Java Spring Boot pull request payloads targeting OWASP Top 10 vulnerability categories. These payloads flow through an Apache Kafka message backbone into a Spring Boot backend that persists them in PostgreSQL for human audit. A React dashboard presents security engineers with a side-by-side diff viewer for original vs. poisoned code snippets, an OWASP-categorized approval/rejection workflow, and a live donut chart tracking audit pass/fail telemetry. The threat category is intentionally hidden from auditors so they must identify vulnerabilities on their own merits.

---

## High-Level Architecture

```
┌──────────────────────┐       JSON files       ┌────────────────────────────────────────┐
│  Python / Ollama     │ ─────────────────────▶  │  Spring Boot 3.4 Backend (:8080)       │
│  Red Team Agent      │   offline-payloads/     │                                        │
│  (gemma3:12b)        │                         │  ┌─────────────┐    Kafka topic         │
│                      │                         │  │  Ingestion   │──audit.pr.ingested──▶ │
└──────────────────────┘                         │  │  (scheduled) │                       │
                                                 │  └─────────────┘    ┌──────────────┐   │
                                                 │                     │  Audit        │   │
                                                 │                ◀────│  (consumer)   │   │
                                                 │                     └──────┬───────┘   │
                                                 │                            │ JPA       │
                                                 │                     ┌──────▼───────┐   │
                                                 │                     │  PostgreSQL   │   │
                                                 │                     │  (aegis_db)   │   │
                                                 │                     └──────┬───────┘   │
                                                 │                            │           │
                                                 │  ┌─────────────┐   ┌──────▼───────┐   │
                                                 │  │ Telemetry   │◀──│  Audit REST  │   │
                                                 │  │ /stats      │   │  /pending    │   │
                                                 │  └──────┬──────┘   │  /evaluate   │   │
                                                 └─────────┼──────────┴──────┬───────┘───┘
                                                           │                 │
                                                      GET /stats      GET & POST
                                                           │                 │
                                                 ┌─────────▼─────────────────▼───────────┐
                                                 │  React 19 Dashboard (:5173)            │
                                                 │                                        │
                                                 │  ┌────────────────────────────────┐    │
                                                 │  │  Code Diff Viewer (split pane) │    │
                                                 │  ├────────────────────────────────┤    │
                                                 │  │  Audit Action Panel            │    │
                                                 │  │  (OWASP dropdown + approve/    │    │
                                                 │  │   reject buttons)              │    │
                                                 │  ├────────────────────────────────┤    │
                                                 │  │  Telemetry Pie Chart           │    │
                                                 │  └────────────────────────────────┘    │
                                                 └────────────────────────────────────────┘
```

The system is organized into three independently deployable domains:

### 1. React UI (`frontend/`)

The Vite-powered React 19 single-page application serves as the security engineer's workstation. It fetches the next pending audit from the backend REST API, renders a split-pane code diff using `react-diff-viewer-continued`, and provides an Audit Action Panel with OWASP category classification and approve/reject controls. On submission, the decision is posted back to the backend and the next pending PR is automatically loaded. A `recharts`-powered donut chart visualizes real-time audit telemetry (pending, passed, false positive, missed threat) by querying the telemetry stats endpoint. The threat category is deliberately not shown to the auditor, enforcing a blind review.

### 2. Spring Boot Kafka Backbone (root Java application)

The backend is a Spring Boot 3.4 application structured around three bounded contexts:

- **Ingestion** — An `OfflinePayloadIngester` scheduled task scans the `offline-payloads/` resource directory every 15 seconds, deserializes JSON files into `PRPayloadDTO` records, and publishes them to the `audit.pr.ingested` Kafka topic via `KafkaProducerService`.
- **Audit** — A `KafkaConsumerService` listens on the same topic, hydrates `PullRequestEntity` JPA entities with `PENDING_AUDIT` status, and persists them to PostgreSQL. The `AuditController` exposes REST endpoints for fetching the next pending PR (`GET /api/v1/audit/pending`) and recording human audit decisions (`POST /api/v1/audit/{prId}/evaluate`). The `AuditService` encodes the scoring logic: approving a poisoned PR results in `AUDIT_FAILED_MISSED_THREAT`, rejecting a clean PR results in `AUDIT_FAILED_FALSE_POSITIVE`, and correct decisions yield `AUDIT_PASSED`.
- **Telemetry** — A `TelemetryService` executes an aggregate `GROUP BY` query against audit statuses and returns a `TelemetryStatsDTO` through `GET /api/v1/telemetry/stats`, powering the frontend chart.

### 3. Air-Gapped Python/Ollama Red Team Agent (`red-team-agent/`)

A standalone Python script that runs entirely offline against a local Ollama instance. On each invocation it randomly selects one of the ten OWASP Top 10 categories (A01–A10), prompts the `gemma3:12b` model with `format="json"` to generate a JSON payload containing a safe code snippet and a subtly poisoned variant, defensively strips any markdown fences from the LLM output, validates the response through Pydantic schema enforcement, and writes the result directly into the backend's `offline-payloads/` directory for automatic ingestion within 15 seconds.

---

## Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| **Docker** & **Docker Compose** | Latest | PostgreSQL 16 and Apache Kafka 3.8 containers |
| **Java** | 21+ | Spring Boot backend runtime |
| **Maven** | 3.9+ | Backend build tool |
| **Node.js** | 20+ | React frontend toolchain |
| **npm** | 10+ | Frontend dependency management |
| **Python** | 3.10+ | Red team agent runtime |
| **Ollama** | Latest | Local LLM inference engine |
| **gemma3:12b** | — | Required Ollama model (`ollama pull gemma3:12b`) |

---

## Quick Start Guide

### 1. Start the Infrastructure

Spin up PostgreSQL and Kafka using the provided Docker Compose file:

```bash
docker compose up -d
```

This starts:
- **PostgreSQL 16** on `localhost:5432` (database: `aegis_db`, user/pass: `aegis`/`aegis`)
- **Apache Kafka 3.8** in KRaft mode (no ZooKeeper) on `localhost:9092`

### 2. Boot the Spring Boot Backend

From the project root:

```bash
./mvnw spring-boot:run
```

Or with a globally installed Maven:

```bash
mvn spring-boot:run
```

The backend starts on `http://localhost:8080`. Hibernate auto-DDL creates the `pull_requests` table on first boot. The offline payload ingester begins scanning every 15 seconds.

### 3. Start the React Frontend

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server starts on `http://localhost:5173` with HMR enabled. Open it in your browser to access the Audit Dashboard.

### 4. Fire the Red Team Agent

In a separate terminal, ensure Ollama is running with the `gemma3:12b` model pulled:

```bash
ollama pull gemma3:12b
```

Then generate adversarial payloads:

```bash
cd red-team-agent
pip install -r requirements.txt
python agent.py
```

Each invocation generates one AI-crafted poisoned payload and writes it to `src/main/resources/offline-payloads/`. The backend ingester picks it up within 15 seconds, publishes it through Kafka, and persists it for audit. The payload appears in the React dashboard within moments.

Run the agent multiple times to build a queue of payloads to review:

```bash
for i in {1..5}; do python agent.py; done
```

---

## Technical Stack

**Backend**
- Java 21
- Spring Boot 3.4.4 (Web, Data JPA, Kafka)
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

**Red Team Agent**
- Python 3.10+
- Ollama (local LLM inference)
- gemma3:12b model
- Pydantic (schema validation)

**Infrastructure**
- Docker Compose
- PostgreSQL 16 (persistent volume)
- Apache Kafka 3.8 (single-node KRaft, no ZooKeeper)
