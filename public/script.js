async function api(path, opts={}) {
  const resp = await fetch(path, opts);
  return resp.json();
}

function log(msg) {
  const el = document.getElementById('log');
  el.textContent = (new Date()).toLocaleTimeString() + ' — ' + msg + '\n' + el.textContent;
}

async function setConfig(key, value) {
  await api('/api/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({key, value}) });
  log(`Config ${key} = ${value}`);
}

async function refreshConfig() {
  const cfg = await api('/api/config');
  document.getElementById('toggle-sql').checked = cfg.sql_injection_enabled;
  document.getElementById('toggle-broken-auth').checked = cfg.broken_auth_enabled;
}

document.getElementById('toggle-sql').addEventListener('change', (e) => {
  setConfig('sql_injection_enabled', e.target.checked);
});

document.getElementById('toggle-broken-auth').addEventListener('change', (e) => {
  setConfig('broken_auth_enabled', e.target.checked);
});

document.getElementById('sql-search').addEventListener('click', async () => {
  const q = document.getElementById('sql-q').value;
  const res = await api('/api/sql?q=' + encodeURIComponent(q));
  document.getElementById('sql-result').textContent = JSON.stringify(res, null, 2);
  log('SQL search executed');
});

document.getElementById('login-btn').addEventListener('click', async () => {
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  const res = await api('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username, password }) });
  document.getElementById('login-result').textContent = JSON.stringify(res, null, 2);
  log('Login attempted');
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  const res = await api('/api/logout', { method: 'POST' });
  document.getElementById('login-result').textContent = JSON.stringify(res, null, 2);
  log('Logout attempted');
});
