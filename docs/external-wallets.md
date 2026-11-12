# External wallet tracking

The dashboard's **Add external wallet** action saves a public receiving address to the signed-in customer's account. It supports up to five Bitcoin or Ethereum mainnet addresses. It does not import a wallet, verify ownership, sign transactions, move funds, or accept recovery phrases/private keys.

Run `npm run db:migrate` before starting or deploying this version. Migration `2026-11-06_external_wallets.sql` creates an owner-scoped address list; no provider credentials are needed. Existing Coinbase OAuth connections remain available when configured.

- `GET /api/investments/wallets` returns saved addresses with native quantities and estimated USD values.
- `POST /api/investments/wallets` accepts only `{ network, address }`; network is `bitcoin` or `ethereum`. Address checksums are validated on the server. Duplicate addresses and additions beyond five are rejected.
- `DELETE /api/investments/wallets/:id` removes only the signed-in customer's saved address. It never affects blockchain funds.

Balances come from Blockstream's Esplora address API (confirmed BTC outputs) and PublicNode's Ethereum mainnet JSON-RPC `eth_getBalance` at the latest block. A single saved address is not the full balance of a wallet with multiple receiving/change addresses. ERC-20 tokens, NFTs, other chains, pending transactions and investment returns are excluded.

USD estimates use Coinbase public exchange rates, with CoinGecko simple prices as a fallback. Quotes older than five minutes from the fallback are rejected. Only completed public price results are cached for one minute; customer balances and addresses are not cached globally. Provider requests are bounded in time and size. Failed balance/price reads remain unavailable rather than zero. Public providers may rate limit or become unavailable; no availability guarantee is implied.

The form explains that public addresses are saved and shared with the selected balance provider. Price feeds receive only coin identifiers. Authenticated routes return `private, no-store`; list, creation and deletion are owner-scoped. The existing admin investment switch pauses additions and balance refreshes while still allowing removal. Add/remove actions appear in the activity audit without request bodies or addresses. No watchlist value is credited to a banking account.

Validation: `npm test` covers checksums, invalid/secret inputs, cross-customer isolation, duplicate/maximum limits, admin pause, provider failures, exact native quantities, quote fallback, dashboard rendering and unsuccessful saves.

Provider references: [Esplora API](https://github.com/Blockstream/esplora/blob/master/API.md), [Ethereum JSON-RPC](https://ethereum.org/developers/docs/apis/json-rpc/), [PublicNode](https://ethereum.publicnode.com), [CoinGecko prices](https://docs.coingecko.com/reference/simple-price).
