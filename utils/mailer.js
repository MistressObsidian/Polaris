// utils/mailer.js
import sgMail from '@sendgrid/mail';
import path from 'path';
import fs from 'fs';

let mailer = null;
let lastMailerError = null;
const DEFAULT_FROM = {
  email: 'support@basecrypto.help',
  name: 'Base Credit',
};
const MIME_TYPES = {
  '.gif': 'image/gif',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.pdf': 'application/pdf',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain',
  '.webp': 'image/webp',
};

// Optional logo for emails
const BRAND_LOGO_URL = String(process.env.BRAND_LOGO_URL || '').trim();
const BRAND_LOGO_PATH = process.env.BRAND_LOGO_PATH || path.join(process.cwd(), 'assets', 'logo-base-credit.svg');
const BRAND_LOGO_CID = 'basecreditlogo';

/**
 * Initialize SendGrid Web API mailer
 */
export async function initMailer() {
  const sendGridApiKey = String(process.env.SENDGRID_API_KEY || '').trim();
  const from = normalizeFromOption(process.env.MAIL_FROM || DEFAULT_FROM);

  if (!from) {
    mailer = null;
    lastMailerError = 'Missing mailer sender configuration';
    console.warn('✉️  Mailer disabled: missing sender configuration');
    return;
  }

  if (!sendGridApiKey) {
    mailer = null;
    lastMailerError = 'Missing SENDGRID_API_KEY';
    console.warn('✉️  Mailer disabled: missing SENDGRID_API_KEY');
    return;
  }

  try {
    mailer = createSendGridMailer({ apiKey: sendGridApiKey, from });
    lastMailerError = null;
    console.log('✉️  Mailer ready: SendGrid API');
    return;
  } catch (e) {
    mailer = null;
    lastMailerError = e?.message || 'SendGrid mailer initialization failed';
    console.warn('⚠️ SendGrid mailer init failed:', e?.message || e);
  }
}

export function isMailerReady() {
  return !!mailer;
}

export function getMailerError() {
  return lastMailerError;
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

function createSendGridMailer({ apiKey, from }) {
  sgMail.setApiKey(apiKey);

  return {
    from,
    async sendMail(mailOptions) {
      const payload = await toSendGridMessage({
        ...mailOptions,
        from: normalizeFromOption(mailOptions.from || from),
      });

      const [response, body] = await sgMail.send(payload);
      return {
        messageId: getSendGridMessageId(response?.headers),
        response: response?.statusCode ? `SendGrid ${response.statusCode}` : 'SendGrid accepted',
        body,
      };
    },
  };
}

async function toSendGridMessage(mailOptions) {
  const message = {
    to: normalizeSendGridRecipients(mailOptions.to),
    from: toSendGridAddress(mailOptions.from),
    subject: mailOptions.subject,
  };

  if (!message.to) throw new Error('SendGrid message missing "to" address');
  if (!message.from) throw new Error('SendGrid message missing "from" address');

  if (typeof mailOptions.text === 'string' && mailOptions.text.trim()) {
    message.text = mailOptions.text;
  }

  if (typeof mailOptions.html === 'string' && mailOptions.html.trim()) {
    message.html = mailOptions.html;
  }

  const replyTo = toSendGridAddress(mailOptions.replyTo);
  if (replyTo) {
    message.replyTo = replyTo;
  }

  const cc = normalizeSendGridRecipients(mailOptions.cc);
  if (cc) {
    message.cc = cc;
  }

  const bcc = normalizeSendGridRecipients(mailOptions.bcc);
  if (bcc) {
    message.bcc = bcc;
  }

  const attachments = await toSendGridAttachments(mailOptions.attachments);
  if (attachments.length) {
    message.attachments = attachments;
  }

  return message;
}

function normalizeSendGridRecipients(value) {
  if (!value) return null;
  if (Array.isArray(value)) {
    const recipients = value.map((entry) => toSendGridAddress(entry)).filter(Boolean);
    return recipients.length ? recipients : null;
  }
  return toSendGridAddress(value);
}

function toSendGridAddress(value) {
  if (!value) return null;

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;

    const match = trimmed.match(/^(.*)<([^>]+)>$/);
    if (match) {
      const name = String(match[1] || '').trim().replace(/^"|"$/g, '');
      const email = String(match[2] || '').trim();
      if (!email) return null;
      return name ? { email, name } : { email };
    }

    return { email: trimmed };
  }

  const email = String(value.email || value.address || '').trim();
  const name = String(value.name || '').trim();
  if (!email) return null;
  return name ? { email, name } : { email };
}

async function toSendGridAttachments(attachments = []) {
  const resolvedAttachments = await Promise.all(
    attachments.map(async (attachment) => {
      if (!attachment) return null;

      const content = await resolveAttachmentContent(attachment);
      if (!content) return null;

      const filePath = String(attachment.path || '').trim();
      const filename = String(attachment.filename || path.basename(filePath) || 'attachment').trim();

      return {
        filename,
        type: String(attachment.contentType || guessContentType(filename || filePath)).trim(),
        disposition: attachment.contentDisposition || (attachment.cid ? 'inline' : 'attachment'),
        content_id: attachment.cid || undefined,
        content: content.toString('base64'),
      };
    })
  );

  return resolvedAttachments.filter(Boolean);
}

async function resolveAttachmentContent(attachment) {
  const filePath = String(attachment.path || '').trim();
  if (filePath) {
    return fs.promises.readFile(filePath);
  }

  const content = attachment.content;
  if (content == null) return null;
  if (Buffer.isBuffer(content)) return content;
  if (ArrayBuffer.isView(content)) {
    return Buffer.from(content.buffer, content.byteOffset, content.byteLength);
  }
  if (typeof content === 'string') {
    const encoding = String(attachment.encoding || 'utf8').trim().toLowerCase();
    return Buffer.from(content, encoding === 'base64' ? 'base64' : 'utf8');
  }

  return Buffer.from(content);
}

function guessContentType(filenameOrPath) {
  const ext = path.extname(String(filenameOrPath || '').trim()).toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
}

function getSendGridMessageId(headers) {
  if (!headers) return null;
  if (typeof headers.get === 'function') {
    return headers.get('x-message-id') || headers.get('X-Message-Id') || null;
  }

  return headers['x-message-id'] || headers['X-Message-Id'] || null;
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