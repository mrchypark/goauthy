const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(tag = 'DIV') { this.tagName = tag; this.children = []; this.dataset = {}; this.listeners = {}; this.hidden = false; this.disabled = false; this.value = ''; this.checked = false; this.textContent = ''; this.attributes = {}; this.style = {}; this.innerHTMLWrites = 0; }
  get textContent() { return this._textContent; }
  set textContent(value) { this._textContent = String(value); this.children = []; }
  set innerHTML(value) { this.innerHTMLWrites++; this._innerHTML = String(value); this.children = []; }
  get innerHTML() { return this._innerHTML || ''; }
  append(...items) { this.children.push(...items); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute(name, value) { this.attributes[name] = value; }
  querySelectorAll(selector) {
    const out = []; const match = (el) => selector === '[data-api-key-input]' ? el.dataset.apiKeyInput !== undefined : selector === '[data-api-key-review]' ? el.dataset.apiKeyReview !== undefined : selector === 'button' ? el.tagName === 'BUTTON' : false;
    const walk = (el) => { for (const child of el.children) { if (match(child)) out.push(child); walk(child); } }; walk(this); return out;
  }
}
const response = (value, status = 200) => ({ status, ok: status >= 200 && status < 300, text: async () => JSON.stringify(value) });
const find = (el, predicate) => { if (predicate(el)) return el; for (const child of el.children) { const found = find(child, predicate); if (found) return found; } return null; };

function setup({ providerIds = ['provider-1'], connector = 'valid', registered = false } = {}) {
  const ids = ['connections-section', 'connections-refresh', 'connections-collection', 'connections-form', 'connections-fields', 'connections-save', 'connections-cancel', 'connections-list', 'connections-status'];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element(id === 'connections-collection' ? 'SELECT' : 'DIV')]));
  elements['connections-refresh'].tagName = elements['connections-save'].tagName = 'BUTTON';
  const calls = []; let status = { registered, version: registered ? 1 : 0 }; let fail = false; let pendingConnector = null; let connectorRequestedResolve; const connectorRequested = new Promise(resolve => { connectorRequestedResolve = resolve; });
  const definition = { id: 'keys', name: 'Keys', enabled: true, auth_method: 'api_key', revision: 1, fields: [], provider_ids: providerIds };
  const connectorInfo = { id: connector === 'wrong-id' ? 'other' : 'provider-1', digest: connector === 'invalid-digest' ? 'bad' : 'D'.repeat(43), header: 'X-API-Key', prefix: '<img src=x onerror=alert(1)>', operations: [{ id: 'lookup', method: 'GET', url: 'https://provider.example/<b>unsafe</b>', response_fields: { account: 'string' } }] };
  const context = { console, confirm: () => true, addEventListener: (name, fn) => { context.windowEvents[name] = fn; }, windowEvents: {}, document: { querySelector: (s) => s[0] === '#' ? elements[s.slice(1)] : null, createElement: (tag) => new Element(tag.toUpperCase()) }, accountDashboard: {
    state: { csrf: 'csrf' }, ready: Promise.resolve(), connectionDeps: {
      status: () => {}, request: async (url, options = {}) => {
        calls.push({ url, options });
        if (fail) throw new Error('Request failed (409). secret-not-for-display');
        if (url.endsWith('/auth-collections')) return response([definition]);
        if (url.endsWith('/connections/keys')) return response([{ id: 'c1', revision: 1, metadata: {} }]);
        if (url.endsWith('/api-key/connector')) { connectorRequestedResolve(); if (connector === 'failed') throw new Error('connector unavailable'); return pendingConnector ? await pendingConnector : response(connectorInfo); }
        if (url.endsWith('/api-key') && (!options.method || options.method === 'GET')) return response(status);
        if (options.method === 'PUT') { status = { registered: true, version: status.version + 1 }; return response(status); }
        if (options.method === 'DELETE') { status = { registered: false, version: status.version }; return response(null, 204); }
        return response({});
      },
    },
  }};
  vm.runInNewContext(fs.readFileSync(__dirname + '/connections.js', 'utf8'), context);
  return { context, elements, calls, connectorRequested, set pendingConnector(value) { pendingConnector = value; }, set fail(value) { fail = value; }, definition };
}
async function contextReady(env) { await env.context.accountDashboard.ready; await env.context.accountDashboard.connections.loadDefinitions(); }
async function open(env) {
  await contextReady(env); const manage = find(env.elements['connections-list'], (el) => el.dataset.connectionApiKey === 'c1' && el.tagName === 'BUTTON'); assert.ok(manage); await manage.listeners.click();
  const panel = find(env.elements['connections-list'], (el) => el.dataset.apiKeyPanel === 'c1');
  return { panel, input: find(panel, (el) => el.dataset.apiKeyInput === 'c1'), save: find(panel, (el) => el.dataset.apiKeySave === 'c1'), revoke: find(panel, (el) => el.dataset.apiKeyRevoke === 'c1'), review: find(panel, (el) => el.dataset.apiKeyReview === 'c1'), connector: find(panel, (el) => el.dataset.apiKeyConnector === 'c1') };
}

async function run() {
  const lifecycle = setup(); const lifecycleUI = await open(lifecycle);
  lifecycleUI.review.checked = true; lifecycleUI.review.listeners.change();
  for (let version = 0; version < 2; version++) {
    lifecycleUI.input.value = 'rotation-secret'; await lifecycleUI.save.listeners.click();
    assert.equal(JSON.parse(lifecycle.calls.at(-1).options.body).version, version); assert.equal(lifecycleUI.input.value, '');
  }
  lifecycleUI.input.value = 'page-secret'; lifecycle.context.windowEvents.pagehide(); assert.equal(lifecycleUI.input.value, '');
  const cancel = find(lifecycleUI.panel, el => el.dataset.apiKeyCancel === 'c1');
  lifecycleUI.input.value = 'cancel-secret'; cancel.listeners.click(); assert.equal(lifecycleUI.input.value, ''); assert.equal(lifecycleUI.review.checked, false);
  const lifecycleManage = find(lifecycle.elements['connections-list'], el => el.dataset.connectionApiKey === 'c1');
  const reads = lifecycle.calls.filter(c => c.url.endsWith('/connector')).length;
  await lifecycleManage.listeners.click(); assert.equal(lifecycle.calls.filter(c => c.url.endsWith('/connector')).length, reads + 1); assert.equal(lifecycleUI.save.disabled, true);
  await lifecycleUI.revoke.listeners.click(); const afterRevoke = lifecycle.calls.length;
  lifecycleUI.input.value = 'revoked-secret'; await lifecycleUI.save.listeners.click(); await lifecycleUI.revoke.listeners.click();
  assert.equal(lifecycleUI.input.value, ''); assert.equal(lifecycle.calls.length, afterRevoke);
  const env = setup(); const ui = await open(env);
  assert.equal(ui.review.checked, false); assert.equal(ui.input.disabled, true); assert.equal(ui.save.disabled, true);
  assert.match(ui.connector.textContent, /<img src=x onerror=alert\(1\)>/); assert.equal(ui.connector.innerHTMLWrites, 0); assert.doesNotMatch(ui.connector.textContent, /secret/);
  ui.review.checked = true; await ui.review.listeners.change({ target: ui.review }); assert.equal(ui.input.disabled, false); assert.equal(ui.save.disabled, false);
  ui.input.value = 'first-secret'; await ui.save.listeners.click(); assert.equal(ui.input.value, ''); assert.deepEqual(JSON.parse(env.calls.at(-1).options.body), { api_key: 'first-secret', version: 0, connector_digest: 'D'.repeat(43) });
  ui.review.checked = false; await ui.review.listeners.change({ target: ui.review }); assert.equal(ui.save.disabled, true); ui.input.value = 'not-sent'; await ui.save.listeners.click(); assert.equal(ui.input.value, '');
  await ui.revoke.listeners.click(); assert.equal(env.calls.at(-1).options.method, 'DELETE');
  for (const call of env.calls.filter((item) => ['PUT', 'DELETE'].includes(item.options.method))) { assert.equal(call.options.headers['X-CSRF-Token'], 'csrf'); assert.equal(call.options.headers['Content-Type'], 'application/json'); }

  const failedSave = setup({ registered: true }); const failedUI = await open(failedSave); failedUI.review.checked = true; await failedUI.review.listeners.change({ target: failedUI.review }); failedSave.fail = true; failedUI.input.value = 'error-secret'; await failedUI.save.listeners.click(); assert.equal(failedUI.input.value, ''); assert.equal(failedUI.review.checked, false); assert.doesNotMatch(find(failedUI.panel, el => el.dataset.apiKeyStatus === 'c1').textContent, /secret-not-for-display|error-secret/); failedSave.fail = false;

  const legacy = setup({ providerIds: [] }); const legacyUI = await open(legacy); assert.equal(legacy.calls.some((call) => call.url.endsWith('/api-key/connector')), false); assert.equal(legacyUI.input.disabled, false); assert.equal(legacyUI.save.disabled, false);
  for (const mode of ['wrong-id', 'invalid-digest']) { const bad = setup({ connector: mode }); const badUI = await open(bad); assert.equal(badUI.save.disabled, true); badUI.input.value = 'blocked'; await badUI.save.listeners.click(); assert.equal(badUI.input.value, ''); assert.equal(bad.calls.some((call) => call.options.method === 'PUT'), false); }
  const failed = setup({ connector: 'failed', registered: true }); const connectorFailedUI = await open(failed); assert.equal(connectorFailedUI.save.disabled, true); assert.equal(connectorFailedUI.revoke.disabled, false); connectorFailedUI.input.value = 'blocked'; await connectorFailedUI.save.listeners.click(); assert.equal(connectorFailedUI.input.value, ''); assert.equal(failed.calls.some((call) => call.options.method === 'PUT'), false);

  const stale = setup(); await contextReady(stale); let releaseConnector; stale.pendingConnector = new Promise(resolve => { releaseConnector = resolve; });
  const manage = find(stale.elements['connections-list'], (el) => el.dataset.connectionApiKey === 'c1'); const opening = manage.listeners.click(); await stale.connectorRequested; const oldPanel = find(stale.elements['connections-list'], (el) => el.dataset.apiKeyPanel === 'c1'); const oldInput = find(oldPanel, (el) => el.dataset.apiKeyInput === 'c1'); await stale.context.accountDashboard.connections.loadDefinitions(); releaseConnector(response({ id: 'provider-1', digest: 'D'.repeat(43), header: 'X', prefix: '', operations: [{ id: 'lookup', method: 'GET', url: 'https://provider.example', response_fields: { account: 'string' } }] })); await opening; assert.notEqual(find(stale.elements['connections-list'], (el) => el.dataset.apiKeyPanel === 'c1'), oldPanel); oldInput.value = 'stale-secret'; const beforeStaleSave = stale.calls.length; const oldSave = find(oldPanel, (el) => el.dataset.apiKeySave === 'c1'); await oldSave.listeners.click(); assert.equal(oldInput.value, ''); assert.equal(stale.calls.length, beforeStaleSave);
  console.log('connection API key UI checks passed');
}
run().catch((error) => { console.error(error); process.exitCode = 1; });
