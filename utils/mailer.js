// utils/mailer.js
import nodemailer from 'nodemailer';
import path from 'path';
import fs from 'fs';

let mailer = null;
const DEFAULT_FROM = {
  email: 'support@basecrypto.help',
  name: 'Base Credit',
};

// Optional logo for emails
const BRAND_LOGO_URL = String(process.env.BRAND_LOGO_URL || '').trim();
const BRAND_LOGO_PATH = process.env.BRAND_LOGO_PATH || path.join(process.cwd(), 'assets', 'logo-base-credit.svg');
const BRAND_LOGO_CID = 'basecreditlogo';

/**
 * Initialize SMTP mailer
 */
export async function initMailer() {
  const host = process.env.SMTP_HOST || 'smtp.sendgrid.net';
  const configuredPort = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = normalizeFromOption(process.env.MAIL_FROM || DEFAULT_FROM);

  if (!host || !user || !pass || !from) {
    console.warn("✉️  Mailer disabled: missing SMTP env vars (SMTP_USER, SMTP_PASS, MAIL_FROM required)");
    return;
  }

  const candidatePorts = [configuredPort, 465, 587, 2525].filter((p, i, arr) => Number.isFinite(p) && arr.indexOf(p) === i);

  for (const port of candidatePorts) {
    try {
      const transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: {
          user,
          pass,
        },
        connectionTimeout: 8000,
        greetingTimeout: 8000,
        socketTimeout: 10000,
      });

      await transporter.verify();
      transporter.from = from;
      mailer = transporter;
      console.log(`✉️  Mailer ready: ${user} via ${host}:${port}`);
      return;
    } catch (e) {
      console.warn(`⚠️ Mailer port ${port} failed:`, e.message);
    }
  }

  mailer = null;
  console.warn("❌ Mailer init failed: all SMTP ports failed");
}

export function isMailerReady() {
  return !!mailer;
}

/**
 * Send an email
 */
export async function sendEmail(to, subject, html, opts = {}) {
  if (!mailer) throw new Error('sendEmail: mailer not initialized');
  if (!to) throw new Error('sendEmail: missing "to" address');

  const defaultReplyTo = process.env.MAIL_REPLY_TO || process.env.SUPPORT_EMAIL || undefined;
  const attachments = Array.isArray(opts.attachments) ? [...opts.attachments] : [];

  if (htmlIncludesBrandLogoCid(html) && !hasBrandLogoAttachment(attachments) && fs.existsSync(BRAND_LOGO_PATH)) {
    attachments.push({
      filename: path.basename(BRAND_LOGO_PATH),
      path: BRAND_LOGO_PATH,
      cid: BRAND_LOGO_CID,
      contentDisposition: 'inline',
    });
  }

  const mailOptions = {
    from: normalizeFromOption(opts.from || mailer.from),
    to,
    subject,
    replyTo: opts.replyTo || defaultReplyTo,
    attachments,
    ...opts,
  };

  if (typeof html === 'string' && html.trim()) {
    mailOptions.html = html;
  }

  try {
    const info = await mailer.sendMail(mailOptions);
    console.log('sendEmail: mail queued', info.messageId || info.response || info);
    return info;
  } catch (e) {
    console.warn('sendEmail failed:', e.message);
    throw e;
  }
}

function normalizeFromOption(from) {
  if (!from) return null;
  const brandName = String(process.env.MAIL_FROM_NAME || process.env.BRAND_NAME || '').trim();
  if (typeof from === 'string') {
    const trimmed = from.trim();
    if (!trimmed) return null;
    if (trimmed.includes('<') && trimmed.includes('>')) return trimmed;
    return brandName ? { address: trimmed, name: brandName } : trimmed;
  }

  const email = String(from.email || from.address || '').trim();
  const name = String(from.name || brandName || '').trim();
  if (!email) return null;

  return name ? { address: email, name } : email;
}

/**
 * Render a simple HTML email template
 */
export function renderEmail(title, bodyHtml) {
  const BRAND_NAME = process.env.BRAND_NAME || 'Base Credit';
  const BRAND_LOGO_SRC = BRAND_LOGO_URL || `cid:${BRAND_LOGO_CID}`;

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

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' })[c]);
}

function htmlIncludesBrandLogoCid(html) {
  return String(html || '').includes(`cid:${BRAND_LOGO_CID}`);
}

function hasBrandLogoAttachment(attachments) {
  return attachments.some((attachment) => {
    const cid = String(attachment?.cid || '').trim();
    const filePath = String(attachment?.path || '').trim();
    return cid === BRAND_LOGO_CID || filePath === BRAND_LOGO_PATH;
  });
}