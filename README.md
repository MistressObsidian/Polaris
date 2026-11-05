# Polaris

Polaris powers the Base Credit website, its customer-facing account pages, and the restricted admin console. The project is a static HTML/CSS/JavaScript frontend served alongside a Node.js and Express backend with PostgreSQL persistence and SendGrid email delivery.

## Current Scope

- User registration, sign-in, password reset, dashboard, accounts, transactions, and settings
- Restricted admin console for user management, balance adjustments, email logs, and template management
- Informational and legal pages such as About, Contact, Privacy, and Terms
- SendGrid Web API integration for registration, password-reset, and admin-triggered emails
- Authenticated users can submit transfers from the account experience; deprecated loan, payment, and simulator flows remain disabled unless they are redesigned and reviewed

## Stack

- Frontend: static HTML, CSS, and vanilla JavaScript
- Backend: Node.js and Express
- Database: PostgreSQL via `pg`
- Email: SendGrid via `@sendgrid/mail`
- Dev tooling: `nodemon`, `http-server`, `concurrently`
- Testing: Node's built-in test runner (`npm test`)

## Scripts

- `npm start` or `npm run api`: start the Express server
- `npm run serve`: serve the static frontend from `frontend/` with `http-server`
- `npm run dev`: start the backend with `nodemon`
- `npm run dev:all`: run the backend and static server together
- `npm test`: run login, admin-session, and project-layout regression tests without changing production data
- `npm run db:migrate:status`: show applied and pending database migrations
- `npm run db:migrate`: apply pending database migrations to the configured Postgres or Neon database
- `npm run db:migrate:new -- <name>`: scaffold a new SQL migration file in `data/migrations`
- `npm run worker:dev`: start the Cloudflare Worker locally
- `npm run worker:deploy -- --keep-vars`: deploy the Worker while preserving dashboard-configured variables
- `npm run worker:admin -- check`: check local admin configuration without displaying credentials
- `npm run worker:admin -- verify-shared`: verify the deployed regular-login admin flow and read-only dashboard APIs

## Local Setup

1. Install dependencies with `npm install`.
2. Provide the required environment variables before starting the server.

Suggested minimum environment variables:

- `DATABASE_URL`
- `JWT_SECRET`
- `SENDGRID_API_KEY`
- `MAIL_FROM`
- `MAIL_REPLY_TO`
- `SUPPORT_EMAIL`
- `BRAND_LOGO_URL`
- `ADMIN_USER`
- `ADMIN_PASS`
- `APP_BASE_URL`
- `PORT`

3. Start the backend with `npm run api`.
4. Open `http://localhost:4000` for the application, or run `npm run serve` if you want a separate static server during development.

Common routes:

- `/`: public landing page
- `/login`: sign-in
- `/register`: registration
- `/dashboard`: authenticated dashboard
- `/accounts`: account overview
- `/transactions`: transaction history
- `/settings`: account settings
- `/admin`: admin dashboard; sign in through `/login` with configured administrator credentials

## Database Migrations

Use the repo migration workflow for schema changes instead of editing Neon manually.

1. Check the current migration state with `npm run db:migrate:status`.
2. Apply pending migrations with `npm run db:migrate`.
3. Create a new migration with `npm run db:migrate:new -- add-user-flag` and put only forward-only SQL into that file.

Notes:

- `data/migrations/0000_baseline_email_primary_schema.sql` bootstraps the current non-destructive email-primary-key schema for new environments.
- `data/schema/postgres-schema.sql` is still a destructive rebuild script because it drops tables first. Do not run it against a populated Neon database.
- `data/schema/postgres-schema-user-email-reference.sql` is a reference schema snapshot for SQL editor use, not the normal migration path.
- The migration runner records applied files in a `schema_migrations` table and will stop if an already-applied migration file is changed later.
- `data/migrations/` SQL files are intended to be tracked in Git; only generated data files should remain ignored.

## Important Pages

- `/` served from `frontend/index.html`: public landing page
- `/login` served from `frontend/login.html`: sign-in
- `/register` served from `frontend/register.html`: user registration
- `/dashboard` served from `frontend/dashboard.html`: authenticated user dashboard
- `/accounts` served from `frontend/accounts.html`: account overview
- `/transactions` served from `frontend/transactions.html`: transaction history
- `/admin` served from `frontend/admin.html`: restricted admin console
- `/about`, `/contact`, `/privacy`, `/terms`: informational and legal pages in `frontend/`

## Project Layout

```text
src/                  Express server, Worker entry point, and backend helpers
frontend/             Public pages, browser scripts, styles, and assets
scripts/
  cloudflare/         Worker administrator verification/configuration utility
  db/                 Database migration runner and scaffolding utility
  email/              Manual SendGrid diagnostic (sends a real email)
tests/                Automated local regression tests
docs/                 Setup guides, inactive examples, and reference reports
data/
  migrations/         Forward-only SQL migrations
  schema/             Reference and explicit rebuild SQL
uploads/              Existing uploaded files (preserved)
```

The root keeps `package.json`, its lockfile, `wrangler.jsonc`, `README.md`, `LICENSE`, and local `.env` configuration. Start commands run from this root. Only `frontend/` is published as static content.

See [Repository layout and cleanup notes](docs/REPOSITORY_LAYOUT.md) for moved paths, removed legacy files, and data-preservation details.

## Notes

- Internal source files and sensitive backend assets should not be served publicly.
- Keep authenticated transfer flows behind login and do not reintroduce deprecated loan, payment, or simulator pages without a separate security and product review.
- Keep secrets out of the repository and configure them through environment variables.
- See [SendGrid deliverability](docs/SENDGRID_DELIVERABILITY.md) for the production mail deliverability checklist.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
