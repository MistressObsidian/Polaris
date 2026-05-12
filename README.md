# Polaris

Polaris powers the Base Credit website, its customer-facing account pages, and the restricted admin console. The project is a static HTML/CSS/JavaScript frontend served alongside a Node.js and Express backend with PostgreSQL persistence and SendGrid email delivery.

## Current Scope

- User registration, sign-in, password reset, dashboard, accounts, transactions, and settings
- Restricted admin console for user management, balance adjustments, email logs, and template management
- Informational and legal pages such as About, Contact, Privacy, and Terms
- SendGrid Web API integration for registration, password-reset, and admin-triggered emails
- Deprecated public intake and simulator flows are disabled and should remain unavailable unless they are redesigned and reviewed

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

## Local Setup

1. Install dependencies with `npm install`.
2. Provide the required environment variables before starting the server.

Suggested minimum environment variables:

- `DATABASE_URL`
- `JWT_SECRET`
- `SENDGRID_API_KEY`
- `MAIL_FROM`
- `SUPPORT_EMAIL`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `APP_BASE_URL`
- `PORT`

3. Start the backend with `npm run api`.
4. Open `http://localhost:4000` for the application, or run `npm run serve` if you want a separate static server during development.

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
- Do not reintroduce public money-movement or fee-collection pages without a separate security and product review.
- Keep secrets out of the repository and configure them through environment variables.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.