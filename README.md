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
- Testing: Cypress configuration is included in the repository

## Scripts

- `npm start` or `npm run api`: start the Express server
- `npm run serve`: serve the static frontend locally with `http-server`
- `npm run dev`: start the backend with `nodemon`
- `npm run dev:all`: run the backend and static server together
- `npm run db:migrate:status`: show applied and pending database migrations
- `npm run db:migrate`: apply pending database migrations to the configured Postgres or Neon database
- `npm run db:migrate:new -- <name>`: scaffold a new SQL migration file in `data/migrations`

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

## Database Migrations

Use the repo migration workflow for schema changes instead of editing Neon manually.

1. Check the current migration state with `npm run db:migrate:status`.
2. Apply pending migrations with `npm run db:migrate`.
3. Create a new migration with `npm run db:migrate:new -- add-user-flag` and put only forward-only SQL into that file.

Notes:

- `data/migrations/0000_baseline_email_primary_schema.sql` bootstraps the current non-destructive email-primary-key schema for new environments.
- `postgres-schema.sql` is still a destructive rebuild script because it drops tables first. Do not run it against a populated Neon database.
- The migration runner records applied files in a `schema_migrations` table and will stop if an already-applied migration file is changed later.

## Important Pages

- `index.html`: public landing page
- `login.html`: sign-in
- `register.html`: user registration
- `dashboard.html`: authenticated user dashboard
- `accounts.html`: account overview
- `transactions.html`: transaction history
- `admin.html`: restricted admin console
- `about.html`, `contact.html`, `privacy.html`, `terms.html`: informational and legal pages

## Notes

- Internal source files and sensitive backend assets should not be served publicly.
- Keep authenticated transfer flows behind login and do not reintroduce deprecated loan, payment, or simulator pages without a separate security and product review.
- Keep secrets out of the repository and configure them through environment variables.
- See [SENDGRID_DELIVERABILITY.md](SENDGRID_DELIVERABILITY.md) for the production mail deliverability checklist.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.