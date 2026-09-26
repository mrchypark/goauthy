async function blacklist() {
  const t = globalThis.GoAuthyI18n?.t || ((key, values = {}) => String(key).replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match));
  const fmt = v => v ? new Date(Number(v) * 1000).toLocaleString() : t('Never');
  shell(t('IP Blacklist'), t('Block specific IP prefixes.'),
    '<div class="panel"><h2>' + t('Blacklist') + '</h2><form id="bl-add" class="toolbar">' +
    '<label for="bl-ip">' + t('IP prefix') + '<input id="bl-ip" required placeholder="203.0.113.0/24"></label>' +
    '<label for="bl-exp">' + t('Expiry') + '<input id="bl-exp" type="datetime-local" required></label>' +
    '<button id="bl-submit" type="submit">' + t('Block IP') + '</button><span id="bl-add-status" role="status"></span></form></div>' +
    '<div id="bl-list"></div>');
  const showError = (node, err) => { node.className = 'error'; node.textContent = err.message; };
  const disableMutations = () => ['bl-ip', 'bl-exp', 'bl-submit'].forEach(id => { document.getElementById(id).disabled = true; });
  const load = async () => {
    const el = document.getElementById('bl-list');
    try {
      const result = await api('/auth/v1/blacklist');
      const rows = result.ips || [];
      el.innerHTML = rows.length ? '<table><thead><tr><th>' + t('IP prefix') + '</th><th>' + t('Expiry') + '</th><th>' + t('Actions') + '</th></tr></thead><tbody>' +
        rows.map(x => '<tr><td>' + esc(x.ip) + '</td><td>' + esc(fmt(x.exp)) + '</td><td><button data-remove="' + esc(x.ip) + '">' + t('Remove') + '</button></td></tr>').join('') +
        '</tbody></table>' : '<p class="state">' + t('No blacklisted IP prefixes.') + '</p>';
    } catch (err) {
      if (/\b404\b/.test(err.message)) {
        disableMutations();
        el.innerHTML = '<p class="state">' + t('IP blacklisting is not enabled in this deployment.') + '</p>';
        return;
      }
      showError(el, err);
    }
  };
  document.getElementById('bl-add').onsubmit = async e => {
    e.preventDefault();
    const status = document.getElementById('bl-add-status');
    status.className = ''; status.textContent = '';
    const ip = document.getElementById('bl-ip').value.trim();
    const exp = Math.floor(new Date(document.getElementById('bl-exp').value).getTime() / 1000);
    if (!Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) { showError(status, Error(t('Expiry must be in the future'))); return; }
    try {
      await api('/auth/v1/blacklist', {method: 'POST', body: JSON.stringify({ip, exp})});
      document.getElementById('bl-ip').value = '';
      document.getElementById('bl-exp').value = '';
      await load();
    } catch (err) { showError(status, err); }
  };
  document.getElementById('bl-list').onclick = async e => {
    const ip = e.target.dataset.remove;
    if (!ip || !confirm(t('Remove {ip} from the blacklist?', {ip}))) return;
    try {
      await api('/auth/v1/blacklist/' + encodeURIComponent(ip), {method: 'DELETE'});
      await load();
    } catch (err) { showError(document.getElementById('bl-list'), err); }
  };
  await load();
}
