// Operational controls share the admin session and API error handling.
const admin = window.AdminConsole;
const $ = id => document.getElementById(id);
const esc = admin.escapeHtml;
const money = value => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(Number(value || 0));
const date = value => value ? new Date(value).toLocaleString() : '—';
const badge = value => `<span class="status-badge status-${esc(value)}">${esc(value)}</span>`;
const specs = {
  users: { body: 'usersTableBody', search: 'userSearch', statuses: ['active', 'suspended'], render: admin.renderUsers },
  transactions: { body: 'transactionsTableBody', statuses: ['pending', 'completed', 'failed', 'cancelled'], render: admin.renderTransactions },
  emails: { body: 'emailsTableBody', statuses: ['pending', 'sent', 'failed'], render: admin.renderEmails },
  transfers: { statuses: ['pending', 'completed', 'failed', 'cancelled'], columns: ['Sender / recipient', 'Method', 'Amount', 'Status', 'Date'], row: row => `<td>${esc(row.user_email)}<br><span class="helper-text">To ${esc(row.recipient_email || row.recipient_name)}</span><br><span class="helper-text">${esc(row.id)}</span></td><td>${esc(row.method.toUpperCase())}</td><td>${money(row.amount)}</td><td>${badge(row.status)}</td><td>${esc(date(row.created_at))}</td>` },
  loans: { statuses: ['pending', 'approved', 'rejected', 'completed', 'cancelled'], columns: ['Customer', 'Requested', 'Term', 'Status / review', 'Action'], row: row => `<td>${esc(row.user_email)}<br><small>${esc(date(row.created_at))}</small></td><td>${money(row.amount)}</td><td>${esc(row.term_months)} months</td><td>${badge(row.status)}${row.reason ? `<p>${esc(row.reason)}</p><small>${esc(row.reviewed_by)} · ${esc(date(row.reviewed_at))}</small>` : ''}</td><td>${row.status === 'pending' ? `<button class="mini-btn" data-review="${esc(row.id)}">Review</button>` : 'Recorded'}</td>` },
  activity: { statuses: ['started', 'succeeded', 'failed'], columns: ['When', 'Action', 'Actor', 'Customer', 'Outcome'], row: row => `<td>${esc(date(row.created_at))}</td><td>${esc(row.action)}</td><td>${esc(row.actor_email)}<br><small>${esc(row.actor_role)}</small></td><td>${esc(row.target_email || 'Platform')}</td><td>${badge(row.outcome)}${row.http_status ? `<br><small>HTTP ${esc(row.http_status)}</small>` : ''}</td>` },
  connections: { section: 'services', columns: ['Customer', 'Last connection update'], row: row => `<td>${esc(row.user_email)}</td><td>${esc(date(row.updated_at))}</td>` },
};
const lists = {};
let platformRevision = null;
let platformDirty = false;
let busy = false;
for (const [kind, spec] of Object.entries(specs)) {
  const section = $(spec.section || kind);
  const host = kind === 'connections' ? $('connectionsList') : section;
  const tools = document.createElement('div');
  tools.className = 'record-tools';
  tools.innerHTML = `${spec.search ? '' : `<input class="search-input" id="${kind}Search" type="search" maxlength="120" placeholder="Search ${kind}" aria-label="Search ${kind}">`}${spec.statuses ? `<select id="${kind}Filter" class="input-base" aria-label="Filter ${kind} by status"><option value="">All statuses</option>${spec.statuses.map(status => `<option value="${status}">${status[0].toUpperCase() + status.slice(1)}</option>`).join('')}</select>` : ''}`;
  if (spec.body) host.querySelector('.panel-head').after(tools);
  else {
    host.append(tools);
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    wrap.innerHTML = `<table><thead><tr>${spec.columns.map(column => `<th>${column}</th>`).join('')}</tr></thead><tbody id="${kind}TableBody"></tbody></table>`;
    host.append(wrap);
    spec.body = `${kind}TableBody`;
  }
  const footer = document.createElement('div');
  footer.className = 'record-footer';
  footer.innerHTML = `<span id="${kind}Count" class="helper-text">Loading records…</span><div><button class="mini-btn" id="${kind}Previous" disabled aria-label="Previous ${kind} page">Previous</button><button class="mini-btn" id="${kind}Next" disabled aria-label="Next ${kind} page">Next</button><button class="mini-btn" id="${kind}Reload" aria-label="Refresh ${kind}">Refresh</button></div>`;
  host.append(footer);
  const status = document.createElement('div');
  status.id = `${kind}Status`; status.className = 'record-status'; status.setAttribute('role', 'status'); host.append(status);
  lists[kind] = { page: 1, total: 0, generation: 0, rows: [], spec, search: $(spec.search || `${kind}Search`), filter: $(`${kind}Filter`) };
  let timer;
  lists[kind].search.addEventListener('input', () => {
    clearTimeout(timer);
    // Invalidate an in-flight response as soon as the search changes.
    lists[kind].generation += 1;
    timer = setTimeout(() => { lists[kind].page = 1; void loadRecords(kind); }, 250);
  });
  lists[kind].filter?.addEventListener('change', () => { lists[kind].page = 1; void loadRecords(kind); });
  $(`${kind}Previous`).addEventListener('click', () => { lists[kind].page -= 1; void loadRecords(kind); });
  $(`${kind}Next`).addEventListener('click', () => { lists[kind].page += 1; void loadRecords(kind); });
  $(`${kind}Reload`).addEventListener('click', () => void loadRecords(kind));
}

async function loadRecords(kind) {
  const list = lists[kind], generation = ++list.generation;
  const query = new URLSearchParams({ page: String(list.page), limit: '25', q: list.search.value.trim(), status: list.filter?.value || '' });
  const status = $(`${kind}Status`);
  status.textContent = 'Loading…'; status.dataset.error = 'false';
  $(`${kind}Previous`).disabled = true; $(`${kind}Next`).disabled = true;
  $(list.spec.body).setAttribute('aria-busy', 'true');
  try {
    const data = await admin.api(`${window.API_BASE}/admin/records/${kind}?${query}`);
    if (generation !== list.generation) return;
    if (data.total > 0 && list.page > Math.ceil(data.total / 25)) { list.page = Math.ceil(data.total / 25); return loadRecords(kind); }
    if (data.total === 0) list.page = 1;
    list.rows = data.rows; list.total = data.total;
    if (list.spec.render) {
      admin.state.overview ||= {};
      admin.state.overview[kind === 'emails' ? 'email_logs' : kind] = data.rows;
      list.spec.render();
    } else {
      $(list.spec.body).innerHTML = data.rows.length ? data.rows.map(row => `<tr>${list.spec.row(row)}</tr>`).join('') : `<tr><td colspan="${list.spec.columns.length}"><div class="empty-state">No ${kind} found.</div></td></tr>`;
    }
    $(`${kind}Count`).textContent = `${data.total.toLocaleString()} records · Page ${list.page} of ${Math.max(1, Math.ceil(data.total / 25))}`;
    status.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    $(`${kind}Previous`).disabled = list.page <= 1;
    $(`${kind}Next`).disabled = list.page * 25 >= data.total;
  } catch (error) {
    if (generation !== list.generation) return;
    status.textContent = `${error.message}. Displayed records have not been refreshed.`;
    status.dataset.error = 'true';
  } finally { if (generation === list.generation) $(list.spec.body).setAttribute('aria-busy', 'false'); }
}

async function loadPlatform(force = false) {
  try {
    const data = await admin.api(`${window.API_BASE}/admin/platform`);
    const names = { database: 'Database', email: 'Email delivery', coinbase: 'Coinbase linking', external_transfers: 'External transfers', payments: 'Payment processing', loan_applications: 'New loan applications' };
    $('serviceGrid').innerHTML = Object.entries(names).map(([key, name]) => `<div class="service-card" data-ready="${['Connected', 'Ready', 'Configured'].includes(data.services[key])}"><small>${name}</small><strong>${esc(data.services[key])}</strong></div>`).join('');
    if (!platformDirty || force) {
      platformRevision = data.features.revision;
      for (const key of ['registration_enabled', 'transfers_enabled', 'investments_enabled']) { $(key).checked = data.features[key]; $(key).disabled = false; }
      platformDirty = false;
      $('savePlatform').disabled = false;
      admin.showStatus($('platformStatus'), `Settings loaded · Revision ${platformRevision}`);
    }
  } catch (error) { admin.showStatus($('platformStatus'), error.message, 'error'); }
}

async function withBusy(form, action) {
  if (busy) return;
  busy = true;
  const controls = [...form.querySelectorAll('button')];
  controls.forEach(button => { button.disabled = true; });
  try { await action(); }
  finally { busy = false; controls.forEach(button => { button.disabled = false; }); }
}
$('platformForm').addEventListener('change', () => { platformDirty = true; });
$('reloadPlatform').addEventListener('click', () => void loadPlatform(true));
$('platformForm').addEventListener('submit', event => {
  event.preventDefault();
  if (platformRevision === null) return;
  void withBusy(event.currentTarget, async () => {
    const flags = Object.fromEntries(['registration_enabled', 'transfers_enabled', 'investments_enabled'].map(key => [key, $(key).checked]));
    try {
      const result = await admin.api(`${window.API_BASE}/admin/platform`, { method: 'PUT', body: JSON.stringify({ ...flags, revision: platformRevision }) });
      platformRevision = result.revision; platformDirty = false;
      admin.showStatus($('platformStatus'), 'Platform controls saved. Changes apply to new requests immediately.', 'success');
      void loadRecords('activity');
    } catch (error) { admin.showStatus($('platformStatus'), error.message, 'error'); }
  });
});
$('revokeSessions').addEventListener('click', async () => {
  const email = admin.state.selectedUser?.user_email;
  if (!email || !window.confirm(`Sign ${email} out of all devices? They can sign in again with their current password.`)) return;
  await withBusy($('selectedUserCard'), async () => {
    try {
      await admin.api(`${window.API_BASE}/admin/users/${encodeURIComponent(email)}/revoke-sessions`, { method: 'POST' });
      admin.showStatus($('sessionStatus'), `All sessions ended for ${email}.`, 'success');
      void loadRecords('activity');
    } catch (error) { admin.showStatus($('sessionStatus'), error.message, 'error'); }
  });
});
$('viewUserActivity').addEventListener('click', () => {
  const email = admin.state.selectedUser?.user_email;
  if (!email) return;
  lists.activity.search.value = email; lists.activity.filter.value = ''; lists.activity.page = 1;
  admin.navigateToSection('activity'); void loadRecords('activity');
});
$('loansTableBody').addEventListener('click', event => {
  const button = event.target.closest('[data-review]');
  if (!button || busy) return;
  const loan = lists.loans.rows.find(row => row.id === button.dataset.review);
  if (!loan) return;
  $('loanReviewForm').hidden = false; $('loanReviewForm').dataset.loanId = loan.id;
  $('loanReviewTarget').textContent = `${loan.user_email} · ${money(loan.amount)} · ${loan.id}`;
  $('loanReason').value = ''; $('loanDecision').value = 'approved';
  admin.showStatus($('loanReviewStatus'), ''); $('loanReason').focus();
});
$('cancelReview').addEventListener('click', () => { $('loanReviewForm').hidden = true; });
$('loanReviewForm').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = { decision: $('loanDecision').value, reason: $('loanReason').value.trim() };
  if (!window.confirm(`Record this loan as ${payload.decision}? This records a review only and does not send funds.`)) return;
  void withBusy(form, async () => {
    try {
      const result = await admin.api(`${window.API_BASE}/admin/loans/${encodeURIComponent(form.dataset.loanId)}/review`, { method: 'PATCH', body: JSON.stringify(payload) });
      form.hidden = true; admin.showStatus($('loanReviewStatus'), result.message, 'success');
      void loadRecords('loans'); void loadRecords('activity');
    } catch (error) { admin.showStatus($('loanReviewStatus'), error.message, 'error'); }
  });
});
async function refreshOperations() {
  if (!admin.getAdminToken()) return;
  await Promise.allSettled([...Object.keys(lists).map(loadRecords), loadPlatform()]);
}
window.addEventListener('admin:refreshed', () => void refreshOperations());
// The inline boot may complete before this module is evaluated.
if (admin.state.overview) void refreshOperations();
const initialSection = location.hash.slice(1);
admin.navigateToSection(['overview', 'users', 'transactions', 'emails', 'transfers', 'loans', 'activity', 'services', 'settings'].includes(initialSection) ? initialSection : 'overview');
