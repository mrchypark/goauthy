async function blacklist() {
  const fmt = v => v ? new Date(Number(v) * 1000).toLocaleString() : 'Never';
  shell('IP Blacklist', 'Block specific IP addresses or view auto-blacklisted entries from failed login attempts.',
    '<div class="panel"><h2>Manual blacklist</h2><form id="bl-add" class="toolbar">' +
    '<label for="bl-ip">IP address<input id="bl-ip" required placeholder="1.2.3.4"></label>' +
    '<label for="bl-expiry">Expiry <span class="hint">Optional</span><input id="bl-expiry" type="datetime-local"></label>' +
    '<label for="bl-comment">Comment <span class="hint">Optional</span><input id="bl-comment" maxlength="256"></label>' +
    '<button type="submit">Block IP</button><span id="bl-add-status" role="status"></span></form></div>' +
    '<div id="bl-manual"></div>' +
    '<div class="panel"><h2>Auto-blacklist</h2><p class="hint">IPs blocked automatically after repeated failed login attempts.</p></div>' +
    '<div id="bl-auto"></div>');
  const showError = (node, err) => { node.className = 'error'; node.textContent = err.message; };
  const loadManual = async () => {
    const el = document.getElementById('bl-manual');
    try {
      const rows = await api('/auth/v1/blacklist');
      el.innerHTML = rows.length ? '<table><thead><tr><th>IP</th><th>Expiry</th><th>Comment</th><th>Actions</th></tr></thead><tbody>' +
        rows.map(x => '<tr><td>' + esc(x.ip) + '</td><td>' + esc(fmt(x.expiry)) + '</td><td>' + esc(x.comment || '—') + '</td><td><button data-remove="' + esc(x.ip) + '">Remove</button></td></tr>').join('') +
        '</tbody></table>' : '<p class="state">No manual blacklist entries.</p>';
    } catch (err) { showError(el, err); }
  };
  const loadAuto = async () => {
    const el = document.getElementById('bl-auto');
    try {
      const rows = await api('/auth/v1/blacklist/auto');
      el.innerHTML = rows.length ? '<table><thead><tr><th>IP</th><th>Failures</th><th>Blocked until</th></tr></thead><tbody>' +
        rows.map(x => '<tr><td>' + esc(x.ip) + '</td><td>' + esc(x.count) + '</td><td>' + esc(fmt(x.until)) + '</td></tr>').join('') +
        '</tbody></table>' : '<p class="state">No auto-blacklisted IPs.</p>';
    } catch (err) { showError(el, err); }
  };
  document.getElementById('bl-add').onsubmit = async e => {
    e.preventDefault();
    const status = document.getElementById('bl-add-status');
    status.className = ''; status.textContent = '';
    const ip = document.getElementById('bl-ip').value.trim();
    const expiryVal = document.getElementById('bl-expiry').value;
    const comment = document.getElementById('bl-comment').value.trim();
    const body = {ip};
    if (expiryVal) {
      const ts = Math.floor(new Date(expiryVal).getTime() / 1000);
      if (!Number.isFinite(ts) || ts <= 0) { showError(status, Error('Invalid expiry')); return; }
      body.expiry = ts;
    }
    if (comment) body.comment = comment;
    try {
      await api('/auth/v1/blacklist', {method: 'POST', body: JSON.stringify(body)});
      document.getElementById('bl-ip').value = '';
      document.getElementById('bl-expiry').value = '';
      document.getElementById('bl-comment').value = '';
      await loadManual();
    } catch (err) { showError(status, err); }
  };
  document.getElementById('bl-manual').onclick = async e => {
    const ip = e.target.dataset.remove;
    if (!ip) return;
    if (!confirm('Remove ' + ip + ' from the blacklist?')) return;
    try {
      await api('/auth/v1/blacklist/' + encodeURIComponent(ip), {method: 'DELETE'});
      await loadManual();
    } catch (err) { showError(document.getElementById('bl-manual'), err); }
  };
  await Promise.all([loadManual(), loadAuto()]);
}
