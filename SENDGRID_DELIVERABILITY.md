# SendGrid Deliverability Checklist

Use this checklist before troubleshooting spam placement for Base Credit service emails.

## 1. Keep Sender Identity Aligned

- Use the same public domain everywhere: `MAIL_FROM`, `MAIL_REPLY_TO`, `SUPPORT_EMAIL`, and `APP_BASE_URL` should all align with `basecrypto.help` in production.
- Keep `BRAND_NAME` and `BRAND_LOGO_URL` aligned with the sender domain so the email header, footer, logo, and links all point to the same brand.
- Do not mix `onrender.com`, `localhost`, or unrelated domains into production email content.

## 2. Verify DNS Authentication

- SPF: publish a TXT record for the apex domain that includes `sendgrid.net`.
- DKIM: configure both SendGrid selectors and keep them active.
- DMARC: publish `_dmarc.basecrypto.help` and keep reporting enabled.
- MX: confirm the support domain can receive replies if `MAIL_REPLY_TO` points to it.

## 3. Configure SendGrid Correctly

- Use SendGrid Domain Authentication for `basecrypto.help`, not just a single sender identity.
- If click or open tracking is ever enabled in SendGrid, first configure a branded tracking domain under `basecrypto.help`.
- Keep click tracking disabled until branded tracking is ready. The application now disables SendGrid click and open tracking by default for transactional mail.
- Review SendGrid sender reputation, blocklist notices, and bounce or spam complaint metrics after each batch of sends.

## 4. Protect API Keys

- Keep live SendGrid API keys in local ignored files or the deployment platform secret store only.
- Do not commit or share `SENDGRID_API_KEY` values in example files, screenshots, or terminal logs.
- Rotate any key immediately if it was pasted into a local helper file and then shared outside your machine.
- Scope the API key to the minimum mail permissions required.

## 5. Keep Transactional Mail Looking Transactional

- Prefer neutral subjects such as profile updates, confirmations, and sign-in notices over alarm-style financial wording.
- Keep one clear purpose per email.
- Include a plain-text body along with HTML.
- Keep footer branding, support contact, and the public site URL consistent.
- Avoid extra promotional blocks, multiple CTA buttons, or unrelated marketing copy.

## 6. Warm and Monitor the Domain

- Start with low-volume sends to real inboxes that will engage normally.
- Avoid sudden spikes from a new or lightly used domain.
- Check Google Postmaster Tools for domain and spam-rate signals.
- Monitor SendGrid activity for deferred messages, blocks, bounces, and complaints.

## 7. Test Before Blaming the App

- Send one test message to Gmail and one to Outlook.
- Check whether the message lands in Inbox, Promotions, Junk, or Spam.
- Inspect the raw message headers to confirm SPF, DKIM, and DMARC all pass.
- If the message body contains rewritten `sendgrid.net` links, branded tracking is still not configured or tracking is enabled somewhere upstream.

## 8. Project-Specific Notes

- The app uses SendGrid Web API mail delivery through [utils/mailer.js](utils/mailer.js).
- Transactional headers and disabled tracking defaults are applied in [utils/mailer.js](utils/mailer.js).
- Default service-email templates live in [server.js](server.js).
- The branded email footer and browser-view link are rendered in [server.js](server.js).
- `sendgrid.env` should remain a local-only helper file and must never contain a key that is shared or committed.