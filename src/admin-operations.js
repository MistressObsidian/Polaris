import { coinbaseConfig } from './investments.js';

export const FEATURE_DEFAULTS = Object.freeze({ registration_enabled: true, transfers_enabled: true, investments_enabled: true });
export function requestError(status, message) { return Object.assign(new Error(message), { status }); }
export async function getFeatures(pool) {
  const { rows } = await pool.query("SELECT value, revision, updated_at FROM platform_settings WHERE key='features'");
  if (!rows.length) throw requestError(503, 'Platform settings are unavailable.');
  return { ...FEATURE_DEFAULTS, ...rows[0].value, revision: rows[0].revision, updated_at: rows[0].updated_at };
}
export async function requireFeature(pool, key) {
  if (!Object.hasOwn(FEATURE_DEFAULTS, key)) throw new Error('Unknown feature');
  if (!(await getFeatures(pool))[key]) throw requestError(503, `${{ registration_enabled: 'New registrations', transfers_enabled: 'Transfers', investments_enabled: 'Investment connections' }[key]} are temporarily paused. Please try again later.`);
}
export async function checkCustomerSession(pool, owner, payload) {
  if (payload.stream && !payload.allowStream) throw requestError(401, 'A full sign-in session is required.');
  const { rows } = await pool.query('SELECT user_email, suspended, session_version FROM users WHERE user_email=$1', [owner]);
  if (!rows.length) throw requestError(401, 'Your session has ended. Please sign in again.');
  if (rows[0].suspended) throw requestError(403, 'Your account is restricted. Please contact support.');
  if (Number(payload.sv || 0) !== Number(rows[0].session_version)) throw requestError(401, 'Your session has ended. Please sign in again.');
  return rows[0];
}
export function customerPreferences(input) {
  if (Object.hasOwn(input, 'transfers_enabled') || Object.hasOwn(input, 'transfersEnabled')) throw requestError(403, 'Only an administrator can change transfer permissions.');
  return Object.fromEntries(Object.entries(input).filter(([key]) => ['theme', 'currency', 'notif_email', 'notifEmail', 'notif_push', 'notifPush'].includes(key)));
}

export async function recordSignIn(pool, email, role, action = 'Sign in') {
  await pool.query("INSERT INTO activity_events (actor_email, actor_role, target_email, action, outcome, http_status, completed_at) VALUES ($1,$2,$1,$3,'succeeded',200,NOW())", [email, role, action]);
}

export async function auditMutation(pool, req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || req.activityTracked) return next();
  req.activityTracked = true;
  const role = req.admin ? 'admin' : 'customer';
  const actor = String(req.admin?.email || req.userId || '');
  const email = String(req.params?.email || (req.path === '/api/admin/users' ? req.body?.email || req.body?.user_email : '') || req.userId || '').toLowerCase().slice(0, 254);
  const actions = {
    'adjust-balance': 'Balance adjustment', password: 'Password changed', preferences: 'Preferences updated',
    profile: 'Profile updated', transfers: 'Transfer submitted', 'email-templates': 'Email templates updated',
    'send-default-email': 'Email sent', 'revoke-sessions': 'Sessions revoked', platform: 'Platform controls updated',
    review: 'Loan review recorded', connect: 'Coinbase link started', coinbase: 'Coinbase disconnected',
  };
  const suffix = req.path.split('/').filter(Boolean).at(-1);
  const action = actions[suffix] || (req.method === 'DELETE' ? 'User deleted' : req.path === '/api/admin/users' ? 'User created' : 'Account updated');
  const { rows } = await pool.query('INSERT INTO activity_events (actor_email, actor_role, target_email, action) VALUES ($1,$2,$3,$4) RETURNING id', [actor, role, email || null, action]);
  const original = res.json.bind(res);
  // Write the intent before running the operation. A failed outcome write leaves
  // an explicit "started" event rather than silently losing the attempt.
  res.json = async body => {
    try {
      const target = typeof body?.user_email === 'string' ? body.user_email.toLowerCase().slice(0, 254) : null;
      await pool.query('UPDATE activity_events SET outcome=$2, http_status=$3, completed_at=NOW(), target_email=COALESCE(target_email,$4) WHERE id=$1', [rows[0].id, res.statusCode < 400 ? 'succeeded' : 'failed', res.statusCode, target]);
    } catch { console.warn('Activity outcome could not be recorded; the attempt remains in the audit history.'); }
    return original(body);
  };
  return next();
}

const RECORDS = {
  users: {
    from: 'users u LEFT JOIN LATERAL (SELECT COUNT(*)::int account_count, COALESCE(SUM(balance),0) balance_total, COALESCE(SUM(available),0) available_total FROM accounts WHERE user_email=u.user_email) a ON true LEFT JOIN user_preferences p ON p.user_email=u.user_email',
    select: 'u.user_email,u.fullname,u.phone,u.accountname,u.suspended,u.created_at,u.updated_at,a.account_count,a.balance_total,a.available_total,COALESCE(p.transfers_enabled,true) transfers_enabled',
    search: "concat_ws(' ',u.user_email,u.fullname,u.accountname)", email: 'u.user_email', order: 'u.created_at DESC,u.user_email', status: "CASE WHEN u.suspended THEN 'suspended' ELSE 'active' END", statuses: ['active','suspended'],
  },
  transactions: { from: 'transactions t LEFT JOIN users u ON u.user_email=t.user_email', select: 't.id,t.user_email,u.fullname,t.direction,t.amount,t.description,t.reference,t.status,t.balance_after,t.created_at', search: "concat_ws(' ',t.user_email,u.fullname,t.reference,t.description)", email: 't.user_email', order: 't.created_at DESC,t.id', status: 't.status', statuses: ['pending','completed','failed','cancelled'] },
  transfers: { from: 'transfers t', select: 't.id,t.user_email,t.recipient_name,t.recipient_email,t.method,t.amount,t.description,t.status,t.created_at', search: "concat_ws(' ',t.user_email,t.recipient_email,t.recipient_name,t.id)", email: 't.user_email', order: 't.created_at DESC,t.id', status: 't.status', statuses: ['pending','completed','failed','cancelled'] },
  loans: { from: 'loans l LEFT JOIN loan_reviews r ON r.loan_id=l.id', select: 'l.id,l.user_email,l.amount,l.term_months,l.status,l.locked,l.created_at,r.reason,r.reviewed_by,r.reviewed_at', search: "concat_ws(' ',l.user_email,l.id)", email: 'l.user_email', order: 'l.created_at DESC,l.id', status: 'l.status', statuses: ['pending','approved','rejected','completed','cancelled'] },
  emails: { from: 'email_logs e', select: 'e.id,e.user_email,e.to_email,e.subject,e.status,e.error,e.created_at', search: "concat_ws(' ',e.user_email,e.to_email,e.subject)", email: 'e.user_email', order: 'e.created_at DESC,e.id', status: 'e.status', statuses: ['pending','sent','failed'] },
  activity: { from: 'activity_events e', select: 'e.id,e.actor_email,e.actor_role,e.target_email,e.action,e.outcome,e.http_status,e.created_at,e.completed_at', search: "concat_ws(' ',e.actor_email,e.target_email,e.action)", email: 'e.target_email', order: 'e.created_at DESC,e.id', status: 'e.outcome', statuses: ['started','succeeded','failed'] },
  connections: { from: 'coinbase_connections c', select: 'c.user_email,c.updated_at', search: 'c.user_email::text', email: 'c.user_email', order: 'c.updated_at DESC,c.user_email' },
};
export function recordQuery(kind, input = {}) {
  const spec = Object.hasOwn(RECORDS, kind) ? RECORDS[kind] : null;
  if (!spec) throw requestError(404, 'Unknown record type');
  const page = Number(input.page || 1), limit = Number(input.limit || 25);
  if (!Number.isSafeInteger(page) || page < 1 || page > 1000000 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw requestError(400, 'Invalid page or page size');
  const clauses = [], params = [];
  const q = String(input.q || '').trim();
  if (q.length > 120) throw requestError(400, 'Search is too long');
  if (q) { params.push(`%${q.replace(/[\\%_]/g, '\\$&')}%`); clauses.push(`${spec.search} ILIKE $${params.length}`); }
  if (input.email) { params.push(String(input.email).toLowerCase()); clauses.push(`${spec.email}=$${params.length}`); }
  if (input.status) {
    if (!spec.statuses?.includes(input.status)) throw requestError(400, 'Invalid status filter');
    params.push(input.status); clauses.push(`${spec.status}=$${params.length}`);
  }
  const where = clauses.length ? ` WHERE ${clauses.join(' AND ')}` : '';
  return { page, limit, params, count: `SELECT COUNT(*)::int total FROM ${spec.from}${where}`, sql: `SELECT ${spec.select} FROM ${spec.from}${where} ORDER BY ${spec.order} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, values: [...params, limit, (page - 1) * limit] };
}

export function registerOperationsRoutes(app, { getPool, auth, mailerStatus = () => false }) {
  const route = handler => async (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    try { return await handler(req, res); }
    catch (error) { return res.status(error.status || 503).json({ error: error.status ? error.message : 'Admin service unavailable. Please refresh and try again.' }); }
  };
  app.get('/api/admin/records/:kind', auth, route(async (req, res) => {
    const query = recordQuery(req.params.kind, req.query);
    const count = await getPool().query(query.count, query.params);
    const rows = await getPool().query(query.sql, query.values);
    res.json({ rows: rows.rows, total: count.rows[0].total, page: query.page, limit: query.limit });
  }));
  app.get('/api/admin/platform', auth, route(async (_req, res) => {
    const features = await getFeatures(getPool());
    const connections = await getPool().query('SELECT COUNT(*)::int total FROM coinbase_connections');
    res.json({ features, services: { database: 'Connected', email: mailerStatus() ? 'Configured' : 'Unavailable', coinbase: coinbaseConfig() ? 'Configured' : 'Application setup required', coinbase_connections: connections.rows[0].total, external_transfers: 'Provider not connected', payments: 'Unavailable', loan_applications: 'Unavailable' } });
  }));
  app.put('/api/admin/platform', auth, route(async (req, res) => {
    const input = req.body || {}, keys = Object.keys(FEATURE_DEFAULTS);
    if (Object.keys(input).some(key => ![...keys, 'revision'].includes(key)) || keys.some(key => typeof input[key] !== 'boolean') || !Number.isSafeInteger(input.revision)) throw requestError(400, 'Provide all feature switches and the current revision.');
    const value = Object.fromEntries(keys.map(key => [key, input[key]]));
    const result = await getPool().query("UPDATE platform_settings SET value=$1::jsonb, revision=revision+1, updated_by=$2, updated_at=NOW() WHERE key='features' AND revision=$3 RETURNING revision", [JSON.stringify(value), req.admin.email, input.revision]);
    if (!result.rowCount) throw requestError(409, 'Settings changed in another session. Refresh before saving.');
    res.json({ ...value, revision: result.rows[0].revision });
  }));
  app.post('/api/admin/users/:email/revoke-sessions', auth, route(async (req, res) => {
    const result = await getPool().query('UPDATE users SET session_version=session_version+1, updated_at=NOW() WHERE user_email=$1 RETURNING user_email', [String(req.params.email).trim().toLowerCase()]);
    if (!result.rowCount) throw requestError(404, 'User not found');
    res.json({ success: true, user_email: result.rows[0].user_email });
  }));
  app.patch('/api/admin/loans/:id/review', auth, route(async (req, res) => {
    const { decision, reason } = req.body || {};
    if (!/^[a-f\d-]{36}$/i.test(req.params.id) || !['approved','rejected','cancelled'].includes(decision) || typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 1000) throw requestError(400, 'Choose a decision and enter a review reason (5–1,000 characters).');
    const client = await getPool().connect();
    try {
      await client.query('BEGIN');
      const result = await client.query("UPDATE loans SET status=$2, locked=true, updated_at=NOW() WHERE id=$1 AND status='pending' RETURNING id,user_email,status", [req.params.id, decision]);
      if (!result.rowCount) throw requestError(409, 'This loan is no longer pending. Refresh the list.');
      await client.query('INSERT INTO loan_reviews (loan_id,decision,reason,reviewed_by) VALUES ($1,$2,$3,$4)', [req.params.id, decision, reason.trim(), req.admin.email]);
      await client.query('COMMIT');
      res.json({ ...result.rows[0], message: 'Review recorded. No funds were disbursed and no fee was collected.' });
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }));
}
