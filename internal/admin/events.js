async function events() {
  const t = globalThis.GoAuthyI18n?.t || ((key, values = {}) => String(key).replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match));
  const levels = ['info', 'notice', 'warning', 'critical'];
  const types = ['InvalidLogins', 'IpBlacklisted', 'IpBlacklistRemoved', 'JwksRotated', 'NewUserRegistered', 'NewRauthyAdmin', 'NewRauthyVersion', 'PossibleBruteForce', 'RauthyStarted', 'RauthyHealthy', 'RauthyUnhealthy', 'SecretsMigrated', 'UserEmailChange', 'UserPasswordReset', 'Test', 'BackchannelLogoutFailed', 'ScimTaskFailed', 'ForcedLogout', 'UserLoginRevoke', 'SuspiciousApiScan', 'LoginNewLocation', 'TokenIssued', 'CredentialStuffing', 'EmailSendError'];
  const now = new Date(), from = new Date(now - 864e5);
  const pad = n => String(n).padStart(2, '0');
  const dtLocal = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  let refreshId = null;
  shell(t('Event Log'), t('Browse authorization and system events with real-time filtering.'), `<div class="panel"><form id="event-filter" class="toolbar"><label for="ev-level">${t('Level')}<select id="ev-level"><option value="">${t('All')}</option>${levels.map(x => `<option value="${x}">${x}</option>`).join('')}</select></label><label for="ev-type">${t('Type')}<select id="ev-type"><option value="">${t('All')}</option>${types.map(x => `<option value="${x}">${x}</option>`).join('')}</select></label><label for="ev-from">${t('From')}<input id="ev-from" type="datetime-local" value="${dtLocal(from)}"></label><label for="ev-until">${t('Until')}<input id="ev-until" type="datetime-local" value="${dtLocal(now)}"></label><label for="ev-limit">${t('Limit')}<input id="ev-limit" inputmode="numeric" value="100"></label><label for="ev-refresh"><input id="ev-refresh" type="checkbox"> ${t('Auto-refresh')}</label><button type="submit">${t('Load')}</button><span class="hint" id="ev-status">${t('Loading…')}</span></form></div><div id="ev-table"></div><div id="ev-pagination"></div>`);
  const status = document.getElementById('ev-status'), table = document.getElementById('ev-table'), pagination = document.getElementById('ev-pagination');
  const formatTs = value => value ? new Date(Number(value)).toLocaleString() : '—';
  const load = async continuationToken => {
    status.className = 'hint'; status.textContent = t('Loading…'); table.innerHTML = ''; pagination.innerHTML = '';
    const level = document.getElementById('ev-level').value || 'info', typ = document.getElementById('ev-type').value;
    const start = Math.floor(new Date(document.getElementById('ev-from').value).getTime() / 1000), until = Math.floor(new Date(document.getElementById('ev-until').value).getTime() / 1000), limit = Number(document.getElementById('ev-limit').value) || 100;
    try {
      const body = {from: start, until, level, limit}; if (typ) body.typ = typ; if (continuationToken) body.continuation_token = continuationToken;
      const result = await api('/auth/v1/events', {method: 'POST', body: JSON.stringify(body)}), rows = Array.isArray(result) ? result : [];
      status.textContent = t('{count} events', {count: rows.length});
      table.innerHTML = rows.length ? `<table><thead><tr><th>${t('Time')}</th><th>${t('Level')}</th><th>${t('Type')}</th><th>${t('IP')}</th><th>${t('Text')}</th></tr></thead><tbody>${rows.map(x => `<tr><td>${esc(formatTs(x.timestamp))}</td><td>${esc(x.level)}</td><td>${esc(x.typ)}</td><td>${esc(x.ip || '—')}</td><td>${esc(x.text || '')}</td></tr>`).join('')}</tbody></table>` : `<p class="state">${t('No events match the current filters.')}</p>`;
      const next = result?._headers?.get?.('X-Continuation-Token');
      if (next) { pagination.innerHTML = `<button id="ev-next" type="button">${t('Next page')}</button>`; document.getElementById('ev-next').onclick = () => load(next); }
    } catch (error) { status.className = 'error'; status.textContent = error.message; }
  };
  document.getElementById('event-filter').onsubmit = event => { event.preventDefault(); load(); };
  document.getElementById('ev-refresh').onchange = event => {
    if (event.target.checked) refreshId = setInterval(load, 5e3);
    else if (refreshId) { clearInterval(refreshId); refreshId = null; }
  };
  await load();
}
