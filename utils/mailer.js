// utils/mailer.js
// Adds initMailer(), sendEmail(to, subject, html, opts) and renderEmail(title, bodyHtml).
// Usage:
//   import { initMailer, sendEmail, renderEmail } from './utils/mailer.js';
//   await initMailer(); // call once at startup
//   await sendEmail('me@example.com', 'Subject', renderEmail('Title', '<p>Body</p>'));

import nodemailer from 'nodemailer';
import path from 'path';
import fs from 'fs';

let mailer = null;

const BRAND_LOGO_PATH = process.env.BRAND_LOGO_PATH
  || path.join(process.cwd(), 'assets', 'logo.png');

const BRAND_LOGO_CID = 'bankswiftlogo';

export async function initMailer() {
  const host = process.env.SMTP_HOST || process.env.EMAIL_HOST;
  const smtpPort = process.env.SMTP_PORT;
  const emailPort = process.env.EMAIL_PORT;
  const port = Number(smtpPort || emailPort || 587);
  const user = process.env.SMTP_USER || process.env.EMAIL_USER;
  const pass = process.env.SMTP_PASS || process.env.EMAIL_PASS;
  const from = process.env.MAIL_FROM || process.env.SMTP_FROM || process.env.EMAIL_FROM || user;
  if (!host || !user || !pass || !from) {
    console.warn('initMailer: SMTP not configured (SMTP_HOST/SMTP_USER/SMTP_PASS + MAIL_FROM/SMTP_FROM/EMAIL_FROM required)');
    return;
  }
  try {
    mailer = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
      pool: false,
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 10000,
    });
    await mailer.verify();
    mailer.from = from;
    console.log('✉️  Mailer ready');
  } catch (e) {
    console.warn('initMailer: Mailer verify failed:', e?.message || e);
    mailer = null;
  }
}

export async function sendEmail(to, subject, html, opts = {}) {
  if (!mailer) {
    console.warn('sendEmail: mailer not initialized; skipping send', { to, subject });
    return false;
  }
  if (!to) throw new Error('sendEmail: missing "to" address');

  const attachments = Array.isArray(opts.attachments) ? opts.attachments : [];

  if (fs.existsSync(BRAND_LOGO_PATH)) {
    attachments.push({
      filename: path.basename(BRAND_LOGO_PATH),
      path: BRAND_LOGO_PATH,
      cid: BRAND_LOGO_CID,
    });
  }

  const mailOptions = {
    from: mailer.from,
    to,
    subject,
    html,
    ...opts,
    attachments,
  };

  try {
    const info = await mailer.sendMail(mailOptions);
    console.log('sendEmail: mail queued', info.messageId || info.response || info);
    return true;
  } catch (e) {
    console.warn('sendEmail failed:', e?.message || e);
    return false;
  }
}

export function renderEmail(title, bodyHtml) {
  const BRAND_NAME = process.env.BRAND_NAME || 'Bank Swift';
  const BRAND_LOGO_SRC = `cid:${BRAND_LOGO_CID}`;
  return `
  <div style="font-family:Arial,sans-serif; background:#f6f8fb; padding:24px;">
    <div style="max-width:600px; margin:0 auto; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e8edf3;">
      <div style="padding:18px 20px; border-bottom:1px solid #4d7fbc; display:flex; align-items:center; gap:12px;">
        <img src="${BRAND_LOGO_SRC}" width="150" alt="${escapeHtml(BRAND_NAME)}" style="display:block; height:auto;" />
      </div>
      <div style="padding:20px;">
        <h2 style="margin:0 0 12px 0; font-size:18px; color:#0f172a;">${escapeHtml(title)}</h2>
        <div style="font-size:14px; color:#334155; line-height:1.5;">
          ${bodyHtml}
        </div>
      </div>
      <div style="padding:16px 20px; border-top:1px solid #e8edf3; font-size:12px; color:#64748b;">
        &copy; ${new Date().getFullYear()} ${escapeHtml(BRAND_NAME)}
      </div>
    </div>
  </div>`;
}

function escapeHtml(s){ if(!s) return ''; return String(s).replace(/[&<>"]/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' })[c]); }