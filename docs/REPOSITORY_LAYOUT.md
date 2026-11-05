# Repository layout

## Active code and commands

| Purpose | Location |
| --- | --- |
| Express backend | `src/server.js` |
| Cloudflare Worker entry point | `src/worker.js` |
| Database access helpers | `src/bank.js` |
| SendGrid mailer | `src/utils/mailer.js` |
| Public website | `frontend/` |
| Cloudflare configuration | Root `wrangler.jsonc` |
| Migration utilities | `scripts/db/` |
| Worker admin utility | `scripts/cloudflare/worker-admin.mjs` |
| Manual email diagnostic | `scripts/email/sendgrid-test.js` |
| Regression tests | `tests/` |

Run the existing npm commands from the project root. `npm start`, `npm run dev`, and the migration commands already point to the new locations. Use `npm run worker:admin -- check` for the relocated admin utility. Tests do not create real customers, send email, or modify the production database.

Keep `package.json`, `package-lock.json`, and `wrangler.jsonc` at the root so the package manager and deployment tooling use one authoritative configuration. The Worker still publishes only `frontend/` and routes `/api/*` to the backend.

## Preserved files

- `.env` and any local `sendgrid.env` belong at the root and remain ignored. They were not changed or removed during cleanup.
- `data/` and `uploads/` were not moved, rewritten, or deleted. Existing database files and uploaded documents may contain user data even when no current source reference points to them.
- SQL migrations and schema references remain under `data/`; ignore rules now allow those source directories to be tracked. Generated runtime data remains ignored. Previously tracked data is not removed from Git by ignore rules.
- All frontend pages and image assets remain in place, including retired-flow notice pages and externally linked branding assets, so existing URLs keep working.
- The former `vmc.pem` was a CSV domain-validation report, not a PEM certificate. Its report data is preserved as `docs/reference/domain-validation.csv`.
- The former `neon_workflow.yml` is preserved as `docs/examples/neon-workflow.yml`. It is an inactive reference and was not installed under `.github/workflows/`; review it before enabling any database-branch automation.

## Removed redundant files

The following nine files were removed after checking their references. Their previously committed versions remain recoverable from Git history (pre-cleanup commit `f1baef1`). No Git history was rewritten.

| Removed paths | Reason |
| --- | --- |
| `scripts/server.js`, `scripts/worker.js`, `scripts/wrangler.jsonc`, `scripts/package.json` | Stale copies of the active application and deployment configuration; not used by the root npm or Wrangler commands. |
| `scripts/auth/generate-jwt.js`, `scripts/auth/generate-jwt-with-new-secret.js` | Unreferenced CommonJS token-generation helpers incompatible with the ESM package; the supported sign-in flow issues sessions server-side. |
| `utils/storage.js` | Unreferenced legacy browser-storage helper outside the public frontend. |
| `cypress.config.js`, `cypress/e2e/hello.cy.js` | Unconfigured Cypress starter files with no installed Cypress dependency or npm command. Active regression tests use Node's test runner. |

Dependencies and generated caches stay in ignored directories. The cleanup does not deploy changes, run migrations, send email, or alter production credentials.
