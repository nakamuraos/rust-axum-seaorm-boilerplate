# Rust Axum + SeaORM Boilerplate

<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-stable-orange.svg?logo=rust" alt="Rust"></a>
  <a href="https://github.com/tokio-rs/axum"><img src="https://img.shields.io/badge/axum-0.8-blue.svg" alt="Axum"></a>
  <a href="https://github.com/SeaQL/sea-orm"><img src="https://img.shields.io/badge/sea--orm-1.1-blue.svg" alt="SeaORM"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://github.com/nakamuraos/rust-axum-seaorm-boilerplate/stargazers"><img src="https://img.shields.io/github/stars/nakamuraos/rust-axum-seaorm-boilerplate?style=social" alt="GitHub stars"></a>
  <a href="https://github.com/nakamuraos/rust-axum-seaorm-boilerplate/network/members"><img src="https://img.shields.io/github/forks/nakamuraos/rust-axum-seaorm-boilerplate?style=social" alt="GitHub forks"></a>
  <a href="https://github.com/nakamuraos/rust-axum-seaorm-boilerplate/issues"><img src="https://img.shields.io/github/issues/nakamuraos/rust-axum-seaorm-boilerplate" alt="GitHub issues"></a>
</p>

A production-ready REST + GraphQL API boilerplate built with [Axum](https://github.com/tokio-rs/axum), [Sea-ORM](https://github.com/SeaQL/sea-orm), and PostgreSQL.

![swagger](./docs/images/swagger.png)
![graphql](./docs/images/graphql.png)
![wrk](./docs/images/wrk.png)

## Features

- **REST API** with versioned routes (`/api/v1/...`)
- **GraphQL** with [Seaography](https://github.com/SeaQL/seaography) + field-level guards
- **OpenAPI/Swagger** auto-generated docs via [utoipa](https://github.com/juhaku/utoipa)
- **JWT authentication** with bcrypt password hashing
- **Role-based access control** — Admin, User roles with auth/admin/owner guards
- **Sea-ORM** with auto-migrations and connection pooling
- **Pagination** — page-based and cursor-based
- **Request validation** — `ValidatedJson` / `ValidatedPath` extractors
- **Middleware** — CORS, request ID (UUID v7), timeout, tracing
- **Structured JSON logging** via [tracing](https://github.com/tokio-rs/tracing)
- **Docker** support with multi-stage builds

## Project Structure

```
src/
├── common/
│   ├── cfg.rs              # Environment-based configuration
│   ├── api_error.rs        # Centralized error handling
│   ├── telemetry.rs        # Logging setup
│   ├── pagination.rs       # Page & cursor pagination
│   ├── middlewares/        # CORS, timeout, request ID, normalize path
│   ├── validation/         # ValidatedJson, ValidatedPath extractors
│   └── utils/              # Auth helpers, shutdown signal
├── database/
│   ├── mod.rs              # Connection pool setup
│   └── migrations/         # Sea-ORM migrations
├── modules/
│   ├── auth/               # Login, register, JWT guards (auth/admin/owner)
│   ├── users/              # CRUD, entities, DTOs, role & status enums
│   └── health/             # Health check endpoint
├── app.rs                  # Router & middleware setup
├── doc.rs                  # OpenAPI config
├── query_root.rs           # GraphQL schema
├── lib.rs
└── main.rs
```

## API Endpoints

| Method     | Path                    | Auth        | Description                  |
| ---------- | ----------------------- | ----------- | ---------------------------- |
| `POST`     | `/api/v1/auth/register` | —           | Register a new user          |
| `POST`     | `/api/v1/auth/login`    | —           | Login, returns JWT           |
| `GET`      | `/api/v1/health`        | —           | Health check                 |
| `GET`      | `/api/v1/users`         | Admin       | List users (paginated)       |
| `POST`     | `/api/v1/users`         | Admin       | Create user                  |
| `GET`      | `/api/v1/users/:id`     | Owner/Admin | Get user                     |
| `PUT`      | `/api/v1/users/:id`     | Owner/Admin | Update user                  |
| `DELETE`   | `/api/v1/users/:id`     | Owner/Admin | Delete user                  |
| `GET/POST` | `/graphql`              | JWT         | GraphQL playground & queries |
| `GET`      | `/docs`                 | —           | Swagger UI                   |

## Getting Started

### Prerequisites

- Rust (latest stable)
- PostgreSQL (or Docker)

### 1. Clone & configure

```shell
git clone https://github.com/nakamuraos/rust-axum-seaorm-boilerplate
cd rust-axum-seaorm-boilerplate
cp .env.sample .env
# Edit .env — at minimum set DATABASE_URL and JWT_SECRET
```

### 2. Start PostgreSQL

```shell
# Using Docker:
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password postgres
```

### 3. Run

```shell
cargo run
```

The server starts at `http://localhost:8080`. Migrations run automatically in development.

- Swagger UI: `http://localhost:8080/docs`
- GraphQL: `http://localhost:8080/graphql`

### Auto-reload (development)

```shell
cargo install cargo-watch
cargo watch -q -x run
# or pipe to jq for formatted logs:
cargo watch -q -x run | jq .
```

## Docker Compose

```shell
cp .env.sample .env
docker-compose up               # or -d for detached
docker-compose down             # stop
```

## Environment Variables

| Variable                  | Default      | Description                      |
| ------------------------- | ------------ | -------------------------------- |
| `APP_ENV`                 | —            | `development` or `production`    |
| `PORT`                    | `8080`       | Server port                      |
| `DATABASE_URL`            | —            | PostgreSQL connection string     |
| `DATABASE_POOL_MAX_SIZE`  | `10`         | Max DB connections               |
| `DATABASE_TIMEOUT`        | `5`          | Connection timeout (seconds)     |
| `DATABASE_RUN_MIGRATIONS` | `true` (dev) | Auto-run migrations on startup   |
| `JWT_SECRET`              | —            | JWT signing key                  |
| `JWT_EXPIRATION_DAYS`     | `7`          | Token lifetime                   |
| `BCRYPT_COST`             | `12`         | Password hashing cost (4–31)     |
| `SWAGGER_ENDPOINT`        | `/docs`      | Swagger UI path                  |
| `SWAGGER_BASIC_AUTH`      | —            | Optional `user:pass` for Swagger |
| `GRAPHQL_ENDPOINT`        | `/graphql`   | GraphQL path                     |
| `GRAPHQL_BASIC_AUTH`      | —            | Optional `user:pass` for GraphQL |
| `RUST_LOG`                | `debug`      | Log level filter                 |

## Production

```shell
# Binary
cargo build --release
# The optimized binary will be available at `target/release/server`
./target/release/server

# Docker
docker build -t axum-app .
docker run -d -p 8080:8080 -v $(pwd)/.env:/app/.env axum-app
```

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.
