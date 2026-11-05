# Admin operations

Open `/admin` and sign in through the regular login page using the server's existing `ADMIN_USER` and `ADMIN_PASS`. Administrator access is checked on the server. Customer sessions cannot use admin endpoints. Credentials remain in private server settings.

## Workspace

- **Users:** search all accounts, filter active/suspended accounts, and page through results. Select **Edit** to load a specific customer. The workspace never automatically chooses or switches customers.
- **User workspace:** edit profiles, suspend/reactivate access, set passwords, change notification/display preferences and transfer permission, adjust the internal ledger, submit supported internal transfers, and send email. An opening balance or adjustment changes the app's ledger; it does not move money through an external provider.
- **Sign out all devices:** invalidates all existing sessions for the selected customer. Password changes and suspension also invalidate existing sessions. Active requests check the account's current status; a connected activity stream checks every 15 seconds.
- **Transactions / transfers / email logs:** server-side search, status filters, and 25-row pagination cover all retained records. Sent email means accepted by the configured provider, not confirmed inbox delivery.
- **Activity history:** successful sign-ins and registrations, password resets, and authenticated customer/admin mutation attempts are recorded from activation of this feature. Each mutation has an actor, target, action, time and outcome. A `started` event means the final outcome has not been confirmed in the audit table. It is not proof that the action failed; inspect the corresponding financial record before repeating an action. Browsing history and events before activation are not reconstructed.
- **Loan reviews:** a pending legacy request can be approved, rejected or cancelled with a reason. Only one decision can be recorded. This is a review record, not loan disbursement or fee collection. New applications remain unavailable.
- **Platform & services:** pause new registration, supported transfers (including admin transfers), or Coinbase linking/holdings retrieval. Customer-specific transfer permission cannot be changed by the customer. Concurrent platform saves use revision checks to prevent silently overwriting another admin's changes.

Email templates and platform switches are stored in PostgreSQL. Local legacy email-template files remain a fallback until templates are first saved to the database. On hosted Workers, default templates are used when no database templates exist.

Accounts with financial history or nonzero balances cannot be deleted; suspend them to retain their records. Activity events are retained independently of deleted empty accounts. Passwords, tokens, email bodies and account numbers are excluded from activity history.

## Provider availability

Coinbase still requires a registered OAuth application and private server configuration; see [Coinbase setup](coinbase-connection.md). Linking is read-only and does not enable trading. External bank and crypto transfers are rejected before funds move because no settlement provider is connected. Payment processing and loan disbursement are unavailable. Feature switches do not configure or activate providers.

Existing transfer statuses are historical ledger records; they have not been reconciled against an external provider.

## Validation and rollout

The additive `2026-10-16_admin_operations.sql` migration adds settings, activity, review records, and session versions. Apply migrations before starting the updated server. The migration has been applied to the configured database for this local run. No customer balance, loan decision, password or account restriction was changed for testing, and no test email was sent.

Run `npm.cmd test` for authorization, audit, settings, session, customer dashboard and Coinbase regression checks. The hosting build can be checked without publishing using the installed Wrangler's `deploy --dry-run --keep-vars` command. A packaging check does not establish live hosting behavior. This task updates the local app; publishing is a separate step.
