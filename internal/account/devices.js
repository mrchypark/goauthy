(() => {
  'use strict';
  const dashboard = globalThis.accountDashboard;
  if (!dashboard || !dashboard.connectionDeps) return;
  const { request, status } = dashboard.connectionDeps;
  const section = document.querySelector('#devices-section');
  if (!section) return;
  const list = document.querySelector('#devices-list');
  const refresh = document.querySelector('#devices-refresh');
  const state = { devices: [], busy: false, generation: 0 };
  const text = (value) => value === undefined || value === null ? '' : String(value);
  const timestamp = (value) => value === undefined || value === null ? '' : text(value);
  function setBusy(busy) {
    state.busy = busy;
    refresh.disabled = busy;
    list.querySelectorAll('button').forEach((button) => { button.disabled = busy || button.dataset.deviceRevoked === 'true'; });
  }
  function render() {
    list.textContent = '';
    if (!state.devices.length) { const empty = document.createElement('p'); empty.className = 'hint'; empty.textContent = 'No authorized devices.'; list.append(empty); return; }
    state.devices.forEach((device) => {
      const row = document.createElement('article'); row.className = 'device-row';
      const heading = document.createElement('h3'); heading.textContent = `Device ${text(device.id)}`;
      const details = document.createElement('p'); details.textContent = `Client: ${text(device.client_id)} · Scopes: ${Array.isArray(device.scopes) ? device.scopes.join(', ') : text(device.scopes)} · Created: ${timestamp(device.created_at_unix_ms)}`;
      row.append(heading, details);
      if (device.revoked_at_unix_ms !== undefined && device.revoked_at_unix_ms !== null) {
        const revoked = document.createElement('p'); revoked.className = 'hint'; revoked.textContent = `Revoked: ${timestamp(device.revoked_at_unix_ms)}`; row.append(revoked);
      } else {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'secondary'; button.dataset.deviceDelete = text(device.id); button.textContent = 'Revoke device'; button.addEventListener('click', () => revokeDevice(device, button)); row.append(button);
      }
      list.append(row);
    });
  }
  async function loadDevices() {
    const generation = ++state.generation; setBusy(true);
    try {
      const result = await request('/auth/v1/account/devices').then((response) => response.json());
      if (generation !== state.generation) return false;
      state.devices = Array.isArray(result) ? result : []; section.hidden = false; render();
      return true;
    } catch (error) {
      if (generation === state.generation) { section.hidden = false; status('devices-status', error.message, true); }
      return false;
    } finally { if (generation === state.generation) setBusy(false); }
  }
  async function revokeDevice(device, button) {
    if (state.busy || !device || device.revoked_at_unix_ms !== undefined && device.revoked_at_unix_ms !== null) return;
    const id = text(device.id); const client = text(device.client_id);
    if (!globalThis.confirm || !globalThis.confirm(`Revoke device ${id} for client ${client}?`)) return;
    state.busy = true; button.disabled = true; refresh.disabled = true;
    try {
      const response = await request(`/auth/v1/account/devices/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf }, body: '' });
      if (response.status !== 204) throw new Error(`Request failed (${response.status}).`);
      if (await loadDevices()) status('devices-status', 'Device revoked.');
    } catch (error) { status('devices-status', error.message, true); button.disabled = false; state.busy = false; refresh.disabled = false; }
  }
  refresh.addEventListener('click', () => { if (!state.busy) loadDevices(); });
  dashboard.ready.then(loadDevices);
  dashboard.devices = { state, loadDevices, revokeDevice, render };
})();
