const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(id = '', tagName = 'div') { this.id = id; this.tagName = tagName; this.children = []; this.dataset = {}; this.textContent = ''; this.disabled = false; this.hidden = true; this.listeners = {}; }
  append(...children) { this.children.push(...children); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  querySelectorAll(selector) { const out = []; const walk = (item) => { (item.children || []).forEach((child) => { if (selector === 'button' && child.tagName === 'button') out.push(child); walk(child); }); }; walk(this); return out; }
}
const makeContext = (withDOM) => {
  const elements = {};
  if (withDOM) ['devices-section', 'devices-refresh', 'devices-status', 'devices-list'].forEach((id) => { elements[id] = new Element(id, id === 'devices-refresh' ? 'button' : 'div'); });
  const calls = []; let deletePending; let deleteError = false;
  const context = { console, confirm: () => true, accountDashboard: { state: { csrf: 'csrf-device' }, ready: Promise.resolve(), connectionDeps: {
    status: (id, message, error) => { elements[id].textContent = message; elements[id].className = error ? 'status error' : 'status'; },
    request: async (url, options = {}) => { calls.push({ url, options }); if (options.method === 'DELETE') { if (deleteError) throw new Error('Request failed (503).'); return new Promise((resolve, reject) => { deletePending = { resolve, reject }; }); } if (url.endsWith('/account/devices')) return { ok: true, status: 200, json: async () => [{ id: 'opaque/device-1', client_id: 'client-a', scopes: ['openid', 'profile'], created_at_unix_ms: 1700000000000 }, { id: 'opaque-device-2', client_id: 'client-b', scopes: ['openid'], created_at_unix_ms: 1700000000001, revoked_at_unix_ms: 1700000000002 }] }; return { ok: true, status: 200, json: async () => ({}) }; },
  } }, document: { querySelector(selector) { return withDOM && selector.startsWith('#') ? elements[selector.slice(1)] || null : null; }, createElement(tag) { return new Element('', tag); } } };
  context.globalThis = context;
  return { context, elements, calls, finishDelete: () => deletePending && deletePending.resolve({ ok: true, status: 204, json: async () => ({}) }), setDeleteError: (value) => { deleteError = value; } };
};

// Missing section markup must be a supported no-op, not a runtime error.
const missing = makeContext(false);
vm.runInNewContext(fs.readFileSync(__dirname + '/devices.js', 'utf8'), missing.context);

const fixture = makeContext(true);
vm.runInNewContext(fs.readFileSync(__dirname + '/devices.js', 'utf8'), fixture.context);
(async () => {
  await fixture.context.accountDashboard.ready;
  await fixture.context.accountDashboard.devices.loadDevices();
  assert.equal(fixture.elements['devices-section'].hidden, false);
  assert.match(fixture.elements['devices-list'].children[0].children[0].textContent, /opaque\/device-1/);
  assert.match(fixture.elements['devices-list'].children[0].children[1].textContent, /client-a/);
  assert.match(fixture.elements['devices-list'].children[1].children[2].textContent, /Revoked/);
  assert.doesNotMatch(fixture.elements['devices-list'].children[0].children[1].textContent, /location|last.used|hardware/i);
  const active = fixture.elements['devices-list'].children[0].children.find((item) => item.dataset.deviceDelete);
  assert.ok(active);
  const revoke = active.listeners.click();
  assert.equal(fixture.calls.filter((item) => item.options.method === 'DELETE').length, 1);
  await fixture.context.accountDashboard.devices.revokeDevice({ id: 'opaque/device-1', client_id: 'client-a' }, active);
  assert.equal(fixture.calls.filter((item) => item.options.method === 'DELETE').length, 1, 'pending revoke suppresses duplicate');
  assert.equal(fixture.calls.at(-1).url, '/auth/v1/account/devices/opaque%2Fdevice-1');
  assert.equal(fixture.calls.at(-1).options.headers['X-CSRF-Token'], 'csrf-device');
  assert.equal(fixture.calls.at(-1).options.body, '');
  fixture.finishDelete(); await revoke;
  assert.match(fixture.elements['devices-status'].textContent, /revoked/i);

  fixture.setDeleteError(true);
  const second = { id: 'opaque/device-1', client_id: 'client-a' };
  const button = new Element('', 'button');
  await fixture.context.accountDashboard.devices.revokeDevice(second, button);
  assert.match(fixture.elements['devices-status'].textContent, /503/);
  assert.equal(fixture.context.accountDashboard.devices.state.devices.length, 2, 'failed revoke preserves list');
  console.log('devices UI checks passed');
})().catch((error) => { console.error(error); process.exitCode = 1; });
