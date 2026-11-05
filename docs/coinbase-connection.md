# Coinbase portfolio connection

The dashboard now supports a separate, read-only Coinbase authorization for each signed-in customer. No customer API keys or Coinbase passwords are collected. Bank balances remain independent of investment valuations. This integration reads Coinbase crypto wallets and vaults; it excludes cash, forex, and derivatives. No trading or transfer permission is requested. P&L is unavailable because this account-balance API does not supply cost basis.

## Activate account linking

1. Register a Coinbase OAuth application in the [Coinbase Developer Platform](https://portal.cdp.coinbase.com/). Follow the [Coinbase OAuth integration guide](https://docs.cdp.coinbase.com/coinbase-app/oauth2-integration/integrations), including any provider approval requirements.
2. Register the exact callback URL. For the local preview it is `http://localhost:4000/api/investments/coinbase/callback`. For the existing production hostname it is `https://polaris.dark-surf-56ad.workers.dev/api/investments/coinbase/callback`. Use separate application configuration for each environment. Open the dashboard on the same origin as the callback.
3. Set these **server-only** environment variables in your ignored `.env` for local development, or as Worker secrets in production. Never put them in frontend files or chat:

   - `COINBASE_CLIENT_ID`: the OAuth application client ID.
   - `COINBASE_CLIENT_SECRET`: its client secret (not a CDP wallet API key).
   - `COINBASE_REDIRECT_URI`: the exact registered callback URL.
   - `INVESTMENT_TOKEN_KEY`: 64 hexadecimal characters generated with a cryptographically secure random generator (32 random bytes). Keep a secure backup; replacing the key requires customers to reconnect.

4. Apply `data/migrations/2026-10-15_coinbase_connections.sql` using the existing migration runner after reviewing migration status (`npm run db:migrate:status`). `npm run db:migrate` applies **all pending** migrations. This new migration only creates connection/state tables and indexes; it does not change balances.
5. Restart the local server, or deploy the configured Worker. Sign in, choose **Connect Coinbase**, and authorize access on Coinbase. The button remains unavailable until the required server configuration is present.

Scopes: `wallet:accounts:read offline_access`. Credentials are encrypted with AES-256-GCM and bound to the customer's email. The flow uses PKCE S256, a browser-bound HTTP-only cookie, and expiring, one-time state. Refresh rotation is serialized with a database row lock. Private API responses are not cached, and tokens never reach browser storage. Disconnect removes stored credentials and requests Coinbase revocation; customers can also revoke the app directly in Coinbase settings.

## Market watch

Public prices require no customer connection or provider key. The server reads [Coinbase Bitcoin statistics](https://docs.cdp.coinbase.com/api-reference/exchange-api/rest-api/products/get-product-stats), [Frankfurter EUR/USD daily reference rates](https://frankfurter.dev/), and [Kraken Bitcoin perpetual futures](https://docs.kraken.com/api-reference/market-data/get-tickers). Sources, timestamps and update types are displayed. Crypto and futures changes compare against the previous 24-hour opening price; FX is a daily reference, not a streaming quote. The dashboard polls every minute. Missing feeds are explicitly unavailable and never replaced by demo prices.

## Validation

`npm test` covers customer isolation, encrypted-token ownership, callback browser binding/replay prevention, read-only scopes, PKCE, refresh rotation, pagination host restrictions, public feed partial failures and dashboard display states. Before enabling for customers, complete a real Coinbase authorization and revocation using the registered app, including a refresh after expiry. Real authorization requires your application credentials and the customer's consent; automated fixtures do not verify provider approval.
