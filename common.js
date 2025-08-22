<!DOCTYPE html>orm utilities: user session, transfers sync (API + SheetDB fallback)
<html lang="en">API server at localhost:3001, SheetDB base URL constant reused across pages.
<head>ion (global) {
<meta charset="UTF-8"/>ps://www.shenzhenswift.online';
<title>Login • Shenzhenswift</title>heetdb.io/api/v1/3g36t35kn6po0';
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>;
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Tahoma,Verdana,sans-serif;background:#f6f7fb;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
  .card{background:#fff;border-radius:16px;padding:32px 28px 28px;box-shadow:0 10px 30px rgba(0,0,0,.12);width:min(420px,94vw);position:relative}
  .brand{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
  .brand h1{font-size:22px;color:#1e3c72;font-weight:700}
  .brand a{text-decoration:none;color:#1e3c72;font-weight:600;font-size:14px}extra);
  h2{margin:8px 0 18px;color:#1e3c72;font-size:20px}
  .form-group{margin-bottom:14px;display:flex;flex-direction:column}
  label{font-weight:600;margin:0 0 6px}
  input{padding:12px 14px;border:2px solid #e2e8f0;border-radius:10px;font-size:15px;transition:border-color .2s}
  input:focus{outline:none;border-color:#667eea}&casesensitive=false`;
  .btn{width:100%;padding:14px 16px;margin-top:4px;background:linear-gradient(45deg,#667eea,#764ba2);color:#fff;font-weight:600;font-size:15px;border:none;border-radius:10px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;transition:.25s}
  .btn:hover{transform:translateY(-2px);box-shadow:0 6px 18px rgba(102,126,234,.3)}
  .btn:disabled{opacity:.55;cursor:not-allowed;transform:none;box-shadow:none}
  .links{display:flex;justify-content:space-between;align-items:center;margin-top:14px;font-size:14px}
  .links a{text-decoration:none;color:#1e3c72;font-weight:600}
  .alert{display:none;margin:10px 0;padding:10px 12px;border-radius:8px;font-size:14px}
  .alert.show{display:block} || !rows.length) return false;
  .alert.error{background:#fde8e8;color:#b91c1c;border:1px solid #fecaca}
  .alert.ok{background:#d1fae5;color:#047857;border:1px solid #a7f3d0}
  .spinner{width:16px;height:16px;border:3px solid #fff;border-top:3px solid transparent;border-radius:50%;animation:spin 1s linear infinite}
  @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
  @media (max-width:500px){.card{padding:24px 6vw}}
</style>;
</head>eturn res.ok;
<body>catch { return false; }
<script src="common.js"></script>
<script>
function showAlert(msg){const el=documenttPatch(reference, fields) {
    try {
      const payload = { data: [{ reference, ...fields }] };
      const res = await fetch(SHEETDB_API_URL, {
        method: 'PATCH',
        headers: sheetAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
      if (res.ok) return true;
    } catch {}
    return sheetInsert([{ formType: 'Transfer', reference, ...fields }]);
  }

  function getUser() {
    try { return JSON.parse(sessionStorage.getItem('loggedInUser') || ''); } catch { return null; }
  }

  function shapeRow(t) {
    return {
      formType: 'Transfer',
      reference: t.reference,
      email: t.email || (getUser() && getUser().email) || '',
      amount: t.amount,
      from: t.from || t.from_account || '',
      to: t.to || t.to_account || '',
      status: t.status || 'Pending',
      dateISO: t.dateISO || new Date().toISOString(),
      network: t.type || t.network || 'Transfer'
    };
  }

  async function recordTransferToSheet(t) {
    try {
      if (!t || !t.reference) return;
      const existing = await sheetSearch({ formType: 'Transfer', reference: t.reference });
      if (Array.isArray(existing) && existing.length) {
        const row = existing[0];
        if (row.status !== t.status) await sheetPatch(t.reference, { status: t.status });
        return;
      }
      await sheetInsert([shapeRow(t)]);
    } catch {}
  }

  async function syncTransferToSheet(t) { return recordTransferToSheet(t); }

  // Export helpers
  global.Platform = Object.assign(global.Platform || {}, {
    sheetSearch, sheetInsert, sheetPatch,
    syncTransferToSheet, recordTransferToSheet,
    SHEETDB_API_URL, SHEETDB_API_TOKEN
  });
})(window);
</script>
</body>
</html>
