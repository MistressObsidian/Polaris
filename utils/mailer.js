// utils/mailer.js
// Adds initMailer(), sendEmail(to, subject, html, opts) and renderEmail(title, bodyHtml).
// Usage:
//   import { initMailer, sendEmail, renderEmail } from './utils/mailer.js';
//   await initMailer(); // call once at startup
//   await sendEmail('me@example.com', 'Subject', renderEmail('Title', '<p>Body</p>'));

import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';

let mailer = null;

export async function initMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.MAIL_FROM || user;
  if (!host || !user || !pass || !from) {
    console.warn('initMailer: SMTP not configured (SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_FROM required)');
    return;
  }
  try {
    mailer = nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });
    await mailer.verify();
    mailer.from = from;
    console.log('✉️  Mailer ready');
  } catch (e) {
    console.warn('initMailer: Mailer verify failed', e);
    mailer = null;
  }
}

export async function sendEmail(to, subject, html, opts = {}) {
  if (!mailer) {
    console.warn('sendEmail: mailer not initialized; skipping send', { to, subject });
    return false;
  }
  if (!to) throw new Error('sendEmail: missing "to" address');
  const mailOptions = { from: mailer.from, to, subject, html, ...opts };
  try {
    const logoPath = path.join(process.cwd(), 'assets', 'logo-128.png');
    if (fs.existsSync(logoPath)) {
      mailOptions.attachments = mailOptions.attachments || [];
      mailOptions.attachments.push({ filename: 'logo-128.png', path: logoPath, cid: 'logo' });
    }
  } catch (e) { /* ignore attachment errors */ }
  try {
    const info = await mailer.sendMail(mailOptions);
    console.log('sendEmail: mail queued', info.messageId || info.response || info);
    return true;
  } catch (e) {
    console.warn('sendEmail failed', e);
    return false;
  }
}

export function renderEmail(title, bodyHtml) {
  const BRAND_NAME = process.env.BRAND_NAME || 'Bank Swift';
  const BRAND_PRIMARY = process.env.BRAND_PRIMARY || '#0b74de';
  const CTA_COLOR = process.env.CTA_COLOR || '#0b74de';
  return `<!doctype html>
  <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
  <body style="font-family:Arial,Helvetica,sans-serif;background:#f5f7fb;padding:20px;">
    <div style="max-width:680px;margin:0 auto;background:#fff;border-radius:6px;overflow:hidden">
      <div style="background:${BRAND_PRIMARY};padding:12px;color:#fff;font-weight:700">${escapeHtml(BRAND_NAME)}</div>
      <div style="padding:20px;color:#333">${bodyHtml}</div>
      <div style="padding:12px;background:#f2f6fa;color:#8aa0b9;font-size:12px">&copy; ${new Date().getFullYear()} ${escapeHtml(BRAND_NAME)}</div>
    </div>
  </body></html>`;
}

function escapeHtml(s){ if(!s) return ''; return String(s).replace(/[&<>"]/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' })[c]); }