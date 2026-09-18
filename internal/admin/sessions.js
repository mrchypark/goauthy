// Session administration screen; admin.js owns its shared API and rendering boundary.
async function sessions() {
  const states = ['Auth', 'Init', 'LoggedOut', 'Unknown'];
  const params = new URLSearchParams(location.search || '');
  const state = states.includes(params.get('session_state')) ? params.get('session_state') : 'Auth';
  const pageSize = params.get('page_size') || '20';
  shell('Sessions', 'Inspect active browser sessions and revoke access at the smallest useful scope.',
    '<div class="panel"><form id="session-filter" class="toolbar">' +
    '<label for="session-state">State<select id="session-state">' + states.map(x => `<option value="${x}">${x}</option>`).join('') +
    '</select></label><label for="session-page-size">Rows<input id="session-page-size" inputmode="numeric" value="' + esc(pageSize) + '"></label>' +
    '<button type="submit">Apply</button><span class="hint" id="session-status">Loading…</span></form></div>' +
    '<div id="session-table"></div><div id="session-paging"></div>' +
    '<div class="panel"><h2>Global logout</h2><p class="warning">Revoke every browser session and OAuth token. This also ends your current administrator session.</p>' +
    '<form id="global-logout"><label><input id="global-ack" type="checkbox"> I understand this administrator session will be lost.</label>' +
    '<button id="global-logout-submit" type="submit" class="button secondary">Revoke all sessions</button><span id="global-result" role="status"></span></form></div>');
  document.getElementById('session-state').value = state;

  const status = document.getElementById('session-status');
  const table = document.getElementById('session-table');
  const paging = document.getElementById('session-paging');
  const showError = (node, err) => { node.className = 'error'; node.textContent = err.message; };
  const formatTime = value => value ? new Date(Number(value) * 1000).toLocaleString() : 'Never';
  const load = async query => {
    status.className = 'hint'; status.textContent = 'Loading…'; table.innerHTML = ''; paging.innerHTML = '';
    try {
      const j = await api('/auth/v1/sessions?' + query.toString());
      const rows = Array.isArray(j) ? j : (j.sessions || []), h = j._headers;
      status.textContent = `${rows.length} ${state} session${rows.length === 1 ? '' : 's'}`;
      table.innerHTML = rows.length ? '<table><thead><tr><th>Subject</th><th>State</th><th>Last seen</th><th>Expires</th><th>Remote IP</th><th>Actions</th></tr></thead><tbody>' + rows.map(x =>
        `<tr><td>${esc(x.user_id || '(anonymous)')}</td><td>${esc(x.state)}</td><td>${esc(formatTime(x.last_seen))}</td><td>${esc(formatTime(x.exp))}</td><td>${esc(x.remote_ip || '—')}</td><td><button data-revoke-session="${esc(x.id)}">Revoke</button>${x.user_id ? ` <button data-force-subject="${esc(x.user_id)}" class="button secondary">Force logout subject</button>` : ''}</td></tr>`).join('') + '</tbody></table>' : '<p class="state">No sessions match this state.</p>';
      const pages = Number(h?.get?.('X-Page-Count') || 0), next = h?.get?.('X-Continuation-Token');
      if (pages && next) {
        const nextQuery = new URLSearchParams(query); nextQuery.set('continuation_token', next);
        paging.innerHTML = `<div class="toolbar"><span class="hint">Page ${query.get('continuation_token') ? 'continued' : '1'} of ${pages}</span><button id="session-next" type="button">Next page</button></div>`;
        document.getElementById('session-next').onclick = () => load(nextQuery);
      }
    } catch (err) { showError(table, err); }
  };

  document.getElementById('session-filter').onsubmit = e => {
    e.preventDefault();
    const q = new URLSearchParams({session_state: document.getElementById('session-state').value, page_size: document.getElementById('session-page-size').value || '20'});
    history.replaceState(null, '', location.pathname + '?' + q.toString());
    return sessions();
  };
  document.getElementById('global-logout').onsubmit = async e => {
    e.preventDefault(); const out = document.getElementById('global-result');
    if (!document.getElementById('global-ack').checked) { out.className = 'error'; out.textContent = 'Acknowledge that your current administrator session will be lost.'; return; }
    if (!confirm('Severe action: revoke every session and token, including this administrator session?')) return;
    try {
      await api('/auth/v1/sessions', {method: 'DELETE'});
      root.innerHTML = '<p class="eyebrow">GoAuthy / administration</p><h1>Global logout complete</h1><p class="state">Every session and token was revoked, including this administrator session. Sign in again to continue.</p>';
    } catch (err) { showError(out, err); }
  };
  table.onclick = async e => {
    const revoke = e.target.dataset.revokeSession, subject = e.target.dataset.forceSubject;
    if (!revoke && !subject) return;
    const message = revoke ? 'Revoke this browser session?' : `Force logout subject ${subject}?`;
    if (!confirm(message)) return;
    const out = document.getElementById('session-status');
    try {
      await api(revoke ? '/auth/v1/sessions/id/' + encodeURIComponent(revoke) : '/auth/v1/sessions/' + encodeURIComponent(subject), {method: 'DELETE'});
      await load(new URLSearchParams(location.search || ''));
    } catch (err) { showError(out, err); }
  };
  const q = new URLSearchParams({session_state: state, page_size: pageSize});
  if (params.get('continuation_token')) q.set('continuation_token', params.get('continuation_token'));
  await load(q);
}
