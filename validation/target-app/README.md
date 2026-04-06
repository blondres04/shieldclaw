# Shield Claw — validation target application

This directory contains a **minimal, intentionally non-vulnerable** Express.js CRUD API backed by PostgreSQL. It exists as a **clean baseline** for Shield Claw pipeline testing: safe patterns only (parameterized SQL, input checks, structured errors). Deliberate weaknesses are **not** included here; they are meant to be introduced later via Pull Requests in a controlled way.

## Stack

- **Node.js** + **Express.js**
- **PostgreSQL** via the **`pg`** driver (no ORM)
- **Docker** / **Docker Compose** for local runs

## Run with Docker Compose

From this directory:

```bash
docker compose up --build
```

- API: [http://localhost:3000](http://localhost:3000)
- Postgres (host access): `localhost:5433` (mapped to avoid clashing with Shield Claw’s default `5432`)

Database schema and three seed users are applied automatically on **first** database volume init via `seed.sql`.

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/users` | List all users |
| `GET` | `/users/:id` | Get one user by numeric id |
| `POST` | `/users` | Create user JSON `{ "name", "email" }` (both required) |
| `DELETE` | `/users/:id` | Delete user by numeric id |

Examples:

```bash
curl -s http://localhost:3000/users
curl -s http://localhost:3000/users/1
curl -s -X POST http://localhost:3000/users -H "Content-Type: application/json" \
  -d '{"name":"Dan Test","email":"dan@example.com"}'
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE http://localhost:3000/users/4
```

## Local development (without Docker)

Requires PostgreSQL with database `targetapp` and user/password matching `server.js` defaults, then:

```bash
npm install
# apply schema + seeds manually if needed
psql ... -f seed.sql
npm start
```

## Security posture (baseline)

- All SQL uses **parameterized** queries (`$1`, `$2`, …).
- **POST /users** validates **name** and **email** as required non-empty strings.
- Route **id** values are validated as positive integers before hitting the database.
- Database operations are wrapped in **try/catch**; errors are logged server-side; clients get generic **5xx** messages (no stack traces).

Use this repo state as the **known-good** reference when reviewing Shield Claw–generated changes.
