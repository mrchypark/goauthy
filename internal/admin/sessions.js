// Session administration screen; admin.js owns its shared API and rendering boundary.
async function sessions() {
  const t = globalThis.GoAuthyI18n?.t || ((key, values = {}) => String(key).replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match));
  const h = (key, values) => esc(t(key, values));
  const states = ['Auth', 'Init', 'LoggedOut', 'Unknown'];
  const params = new URLSearchParams(location.search || '');
  const state = states.includes(params.get('session_state')) ? params.get('session_state') : 'Auth';
  const rawPageSize = params.get('page_size'), parsedPageSize = Number(rawPageSize);
  const pageSize = rawPageSize && Number.isInteger(parsedPageSize) && parsedPageSize >= 1 && parsedPageSize <= 65535 ? String(parsedPageSize) : '20';
  shell(t('Sessions'), t('Inspect active browser sessions and revoke access at the smallest useful scope.'),
    '<div class="panel"><form id="session-filter" class="toolbar">' +
    '<label for="session-state">' + h('State') + '<select id="session-state">' + states.map(x => `<option value="${x}">${x}</option>`).join('') +
    '</select></label><label for="session-page-size">' + h('Rows') + '<input id="session-page-size" type="number" min="1" max="65535" step="1" inputmode="numeric" value="' + esc(pageSize) + '"></label>' +
    '<button type="submit">' + h('Apply') + '</button><span class="hint" id="session-status">' + h('Loading…') + '</span></form><p class="hint">' + h('Requested page size; the server applies its paging threshold and returns smaller result sets in full.') + '</p></div>' +
    '<div id="session-table"></div><div id="session-paging"></div>' +
    '<div class="panel"><h2>' + h('Global logout') + '</h2><p class="warning">' + h('Revoke every browser session and OAuth token. This also ends your current administrator session.') + '</p>' +
    '<form id="global-logout"><label><input id="global-ack" type="checkbox"> ' + h('I understand this administrator session will be lost.') + '</label>' +
    '<button id="global-logout-submit" type="submit" class="button secondary">' + h('Revoke all sessions') + '</button><span id="global-result" role="status"></span></form></div>');
  document.getElementById('session-state').value = state;

  const status = document.getElementById('session-status');
  const table = document.getElementById('session-table');
  const paging = document.getElementById('session-paging');
  const showError = (node, err) => { node.className = 'error'; node.textContent = err.message; };
  const formatTime = value => value ? new Date(Number(value) * 1000).toLocaleString() : t('Never');
  const load = async query => {
      status.className = 'hint'; status.textContent = t('Loading…'); table.innerHTML = ''; paging.innerHTML = '';
    try {
      const j = await api('/auth/v1/sessions?' + query.toString());
      const rows = Array.isArray(j) ? j : (j.sessions || []), headers = j._headers;
      status.textContent = t('{count} sessions in {state}', {count: rows.length, state});
      table.innerHTML = rows.length ? '<table><thead><tr><th>' + h('Subject') + '</th><th>' + h('State') + '</th><th>' + h('Last seen') + '</th><th>' + h('Expires') + '</th><th>' + h('Remote IP') + '</th><th>' + h('Actions') + '</th></tr></thead><tbody>' + rows.map(x =>
        `<tr><td>${esc(x.user_id || t('(anonymous)'))}</td><td>${esc(x.state)}</td><td>${esc(formatTime(x.last_seen))}</td><td>${esc(formatTime(x.exp))}</td><td>${esc(x.remote_ip || '—')}</td><td><button data-revoke-session="${esc(x.id)}">${h('Revoke')}</button>${x.user_id ? ` <button data-force-subject="${esc(x.user_id)}" class="button secondary">${h('Force logout subject')}</button>` : ''}</td></tr>`).join('') + '</tbody></table>' : `<p class="state">${h('No sessions match this state.')}</p>`;
      const pages = Number(headers?.get?.('X-Page-Count') || 0), next = headers?.get?.('X-Continuation-Token');
      if (pages && next) {
        const nextQuery = new URLSearchParams(query); nextQuery.set('continuation_token', next);
        paging.innerHTML = `<div class="toolbar"><span class="hint">${h('Page {page} of {pages}', {page: query.get('continuation_token') ? t('continued') : '1', pages})}</span><button id="session-next" type="button">${h('Next page')}</button></div>`;
        document.getElementById('session-next').onclick = () => load(nextQuery);
      }
    } catch (err) { showError(table, err); }
  };

  document.getElementById('session-filter').onsubmit = e => {
    e.preventDefault();
    const raw = document.getElementById('session-page-size').value, size = Number(raw);
    if (!Number.isInteger(size) || size < 1 || size > 65535) { status.className = 'error'; status.textContent = h('Rows') + ' (1–65535)'; document.getElementById('session-page-size').focus(); return; }
    const q = new URLSearchParams({session_state: document.getElementById('session-state').value, page_size: String(size)});
    history.replaceState(null, '', location.pathname + '?' + q.toString());
    return sessions();
  };
  document.getElementById('global-logout').onsubmit = async e => {
    e.preventDefault(); const out = document.getElementById('global-result');
    if (!document.getElementById('global-ack').checked) { out.className = 'error'; out.textContent = t('Acknowledge that your current administrator session will be lost.'); return; }
    if (!confirm(t('Severe action: revoke every session and token, including this administrator session?'))) return;
    try {
      await api('/auth/v1/sessions', {method: 'DELETE'});
      root.innerHTML = '<p class="eyebrow">' + h('GoAuthy / administration') + '</p><h1>' + h('Global logout complete') + '</h1><p class="state">' + h('Every session and token was revoked, including this administrator session. Sign in again to continue.') + '</p>';
    } catch (err) { showError(out, err); }
  };
  table.onclick = async e => {
    const revoke = e.target.dataset.revokeSession, subject = e.target.dataset.forceSubject;
    if (!revoke && !subject) return;
    const message = revoke ? t('Revoke this browser session?') : t('Force logout subject {subject}?', {subject});
    if (!confirm(message)) return;
    const out = document.getElementById('session-status');
    try {
      await api(revoke ? '/auth/v1/sessions/id/' + encodeURIComponent(revoke) : '/auth/v1/sessions/' + encodeURIComponent(subject), {method: 'DELETE'});
      await load(new URLSearchParams(location.search || ''));
    } catch (err) { showError(out, err); }
  };
  const q = new URLSearchParams({session_state: state, page_size: pageSize});
  const invalidPageSize = rawPageSize !== null && rawPageSize !== pageSize;
  const invalidState = params.has('session_state') && params.get('session_state') !== state;
  if (params.get('continuation_token') && !invalidPageSize && !invalidState) q.set('continuation_token', params.get('continuation_token'));
  if (invalidPageSize || invalidState) history.replaceState(null, '', location.pathname + '?' + q.toString());
  await load(q);
}
