const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(tag = 'DIV') { this.tagName = tag; this.children = []; this.dataset = {}; this.listeners = {}; this.hidden = false; this.disabled = false; this.value = ''; this.textContent = ''; this.attributes = {}; }
  append(...items) { this.children.push(...items); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; if (name === 'href') delete this.href; }
  set innerHTML(_) { throw new Error('unsafe HTML'); }
  set textContent(value) { this._textContent = String(value); this.children = []; }
  get textContent() { return this._textContent || ''; }
  querySelectorAll(selector) { const out = []; const match = el => selector === 'button' && el.tagName === 'BUTTON'; const walk = el => { for (const child of el.children) { if (match(child)) out.push(child); walk(child); } }; walk(this); return out; }
}
const response = (value, status = 200) => ({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(value) });
const rawResponse = text => ({ ok: true, status: 200, text: async () => text });
const find = (el, predicate) => { if (predicate(el)) return el; for (const child of el.children) { const found = find(child, predicate); if (found) return found; } return null; };

function setup({ initial = { state: 'draft', version: 0, connected: false, provider_id: '', scopes: [] }, start = { authorization_url: 'https://provider.example/authorize?state=one' } } = {}) {
  const ids = ['connections-section', 'connections-refresh', 'connections-collection', 'connections-form', 'connections-fields', 'connections-save', 'connections-cancel', 'connections-list', 'connections-status'];
  const elements = Object.fromEntries(ids.map(id => [id, new Element(id === 'connections-collection' ? 'SELECT' : 'DIV')]));
  elements['connections-refresh'].tagName = elements['connections-save'].tagName = 'BUTTON';
  const calls = []; let currentStatus = initial; let fail = false; let pendingStatus = null; let statusRequestedResolve; const statusRequested = new Promise(resolve => { statusRequestedResolve = resolve; });
  const definition = { id: 'oauth', name: 'OAuth', enabled: true, auth_method: 'oauth2', revision: 1, fields: [], provider_ids: ['provider-1', 'provider-2'] };
  const context = { console, URL, confirm: () => true, addEventListener: () => {}, document: { querySelector: s => s[0] === '#' ? elements[s.slice(1)] : null, createElement: tag => new Element(tag.toUpperCase()) }, accountDashboard: { state: { csrf: 'csrf' }, ready: Promise.resolve(), connectionDeps: {
    status: () => {}, request: async (url, options = {}) => {
      calls.push({ url, options });
      if (fail) throw new Error('Request failed (409). no secret');
      if (url.endsWith('/auth-collections')) return response([definition]);
      if (url.endsWith('/connections/oauth')) return response([{ id: 'c1', revision: 1, metadata: {} }]);
      if (url.endsWith('/oauth2') && (!options.method || options.method === 'GET')) { statusRequestedResolve(); return pendingStatus ? await pendingStatus : response(currentStatus); }
      if (options.method === 'POST' && url.endsWith('/oauth2')) return response(start);
      if (options.method === 'POST' && url.endsWith('/refresh')) { currentStatus = { ...currentStatus, state: 'ready', connected: true, version: currentStatus.version + 1, provider_id: 'provider-1', scopes: ['openid'] }; return response(currentStatus); }
      if (options.method === 'POST' && url.endsWith('/reconnect')) { currentStatus = { state: 'reconnecting', version: currentStatus.version, connected: false, provider_id: '', scopes: [] }; return response(currentStatus); }
      if (options.method === 'DELETE') { currentStatus = { state: 'revoked', version: currentStatus.version, connected: false, provider_id: '', scopes: [] }; return response(null, 204); }
      return response({});
    },
  } } };
  vm.runInNewContext(fs.readFileSync(__dirname + '/connections.js', 'utf8'), context);
  return { context, elements, calls, set fail(value) { fail = value; }, set pendingStatus(value) { pendingStatus = value; }, statusRequested, definition };
}
async function ready(env) { await env.context.accountDashboard.ready; await env.context.accountDashboard.connections.loadDefinitions(); }
async function open(env) { await ready(env); const manage = find(env.elements['connections-list'], e => e.dataset.connectionOauth2 === 'c1' && e.tagName === 'BUTTON'); await manage.listeners.click(); const panel = find(env.elements['connections-list'], e => e.dataset.oauth2Panel === 'c1' && e.tagName === 'DIV'); return { panel, start: find(panel, e => e.dataset.oauth2Start === 'c1'), continue: find(panel, e => e.dataset.oauth2Continue === 'c1'), check: find(panel, e => e.dataset.oauth2Check === 'c1'), refresh: find(panel, e => e.dataset.oauth2Refresh === 'c1'), revoke: find(panel, e => e.dataset.oauth2Revoke === 'c1'), reconnect: find(panel, e => e.dataset.oauth2Reconnect === 'c1') }; }

async function run() {
  const unopened = setup(); await ready(unopened);
  for (const key of ['oauth2Start', 'oauth2Refresh', 'oauth2Revoke', 'oauth2Reconnect']) assert.equal(find(unopened.elements['connections-list'], e => e.dataset[key] === 'c1').disabled, true);
  const draft = setup(); const ui = await open(draft);
  assert.equal(draft.calls.filter(c => c.options.method === 'POST').length, 0);
  await ui.start.listeners.click(); const startCall = draft.calls.at(-1); assert.equal(startCall.options.method, 'POST'); assert.deepEqual(JSON.parse(startCall.options.body), { provider_id: 'provider-1' }); assert.equal(startCall.options.headers['X-CSRF-Token'], 'csrf'); assert.equal(ui.continue.hidden, false); const anchor = find(ui.panel, e => e.tagName === 'A'); assert.equal(anchor.href, 'https://provider.example/authorize?state=one'); assert.equal(anchor.target, '_blank'); assert.equal(anchor.rel, 'noopener noreferrer');
  assert.equal(startCall.url, '/auth/v1/account/connections/oauth/c1/oauth2');
  const afterStart = draft.calls.length; await ui.start.listeners.click(); assert.equal(draft.calls.length, afterStart);
  await ui.check.listeners.click(); assert.equal(ui.continue.hidden, true); assert.equal(ui.continue.href, undefined); assert.equal(ui.start.disabled, false);
  draft.context.accountDashboard.connections.state.busy = true;
  const whileBusy = draft.calls.length; await ui.check.listeners.click(); await ui.start.listeners.click(); assert.equal(draft.calls.length, whileBusy);
  draft.context.accountDashboard.connections.state.busy = false;
  find(ui.panel, e => e.dataset.oauth2Close === 'c1').listeners.click();
  await ui.start.listeners.click(); await ui.check.listeners.click(); assert.equal(draft.calls.length, whileBusy);

  const readyEnv = setup({ initial: { state: 'ready', version: 4, connected: true, account_id: 'acct', provider_id: 'provider-1', scopes: ['openid'] } }); const readyUI = await open(readyEnv); await readyUI.refresh.listeners.click(); assert.equal(JSON.parse(readyEnv.calls.at(-1).options.body).version, 4); assert.equal(readyEnv.calls.at(-1).options.headers['X-CSRF-Token'], 'csrf'); await readyUI.revoke.listeners.click(); assert.equal(readyEnv.calls.at(-1).options.method, 'DELETE'); assert.equal(JSON.parse(readyEnv.calls.at(-1).options.body).version, 5); assert.equal(readyUI.panel.dataset.oauth2State, 'revoked');
  assert.equal(readyEnv.calls.at(-1).url, '/auth/v1/account/connections/oauth/c1/oauth2');
  await readyUI.reconnect.listeners.click(); assert.equal(readyEnv.calls.at(-1).url, '/auth/v1/account/connections/oauth/c1/oauth2/reconnect');
  assert.equal(readyUI.panel.dataset.oauth2State, 'reconnecting'); assert.equal(readyUI.start.disabled, false);
  await readyUI.start.listeners.click(); assert.deepEqual(JSON.parse(readyEnv.calls.at(-1).options.body), { provider_id: 'provider-1' });

  for (const oauthState of ['refreshing', 'uncertain']) {
    const env = setup({ initial: { state: oauthState, version: 2, connected: false, provider_id: 'provider-1', scopes: ['read'] } }); const control = await open(env);
    const before = env.calls.length; await control.start.listeners.click(); await control.refresh.listeners.click(); await control.reconnect.listeners.click();
    assert.equal(env.calls.length, before); assert.equal(control.revoke.disabled, false);
    await control.revoke.listeners.click(); assert.equal(env.calls.at(-1).options.method, 'DELETE');
  }
  for (const disabled of [true, false]) {
    const env = setup({ initial: { state: 'ready', version: 1, connected: true, account_id: '<b>account</b>', provider_id: disabled ? 'provider-1' : 'removed-provider', scopes: [] } });
    env.definition.enabled = !disabled; const control = await open(env);
    const before = env.calls.length; await control.refresh.listeners.click(); assert.equal(env.calls.length, before);
    assert.equal(control.revoke.disabled, false); assert.match(find(control.panel, e => e.dataset.oauth2Status === 'c1').textContent, /<b>account<\/b>/);
    env.context.confirm = () => false; await control.revoke.listeners.click(); assert.equal(env.calls.length, before);
    env.context.confirm = () => true; await control.revoke.listeners.click(); assert.equal(env.calls.at(-1).options.method, 'DELETE');
  }
  for (const invalid of [{ connected: false }, { account_id: {} }, { account_id: '' }, { scopes: ['two scopes'] }, { scopes: [''] }, { version: -1 }, { version: 1.5 }]) {
    const env = setup({ initial: { state: 'ready', version: 1, connected: true, account_id: 'account', provider_id: 'provider-1', scopes: ['read'], ...invalid } });
    const control = await open(env); const before = env.calls.length; await control.refresh.listeners.click(); await control.revoke.listeners.click();
    assert.equal(env.calls.length, before); assert.equal(control.panel.dataset.oauth2State, undefined);
  }

  const failEnv = setup({ initial: { state: 'ready', version: 2, connected: true, account_id: 'acct', provider_id: 'provider-1', scopes: [] } }); const failUI = await open(failEnv); failEnv.fail = true; await failUI.refresh.listeners.click(); assert.equal(failUI.refresh.disabled, true); assert.equal(failUI.revoke.disabled, true); failEnv.fail = false; const beforeCheck = failEnv.calls.length; await failUI.check.listeners.click(); assert.equal(failEnv.calls.length, beforeCheck + 1); assert.equal(failUI.panel.dataset.oauth2State, 'ready'); await failUI.refresh.listeners.click(); assert.equal(failEnv.calls.at(-1).options.method, 'POST');

  const unsafe = setup(); unsafe.pendingStatus = rawResponse('{"state":"ready","version":9007199254740992,"connected":true,"provider_id":"provider-1","scopes":[]}'); const unsafeUI = await open(unsafe); assert.equal(unsafeUI.panel.dataset.oauth2State, undefined); assert.equal(unsafeUI.start.disabled, true); assert.equal(unsafe.calls.filter(c => c.options.method === 'POST').length, 0);
  const malformed = setup(); malformed.pendingStatus = rawResponse('{"state":"ready","version":1,"connected":true,"provider_id":"provider-1","scopes":[1]}'); const malformedUI = await open(malformed); assert.equal(malformedUI.panel.dataset.oauth2State, undefined); assert.equal(malformedUI.refresh.disabled, true);
  for (const destination of ['javascript:alert(1)', 'http://provider.example', 'https://user:password@provider.example', 'https://provider.example/#fragment', ' https://provider.example', 'https://provider.example/\nsecret']) {
    const badURL = setup({ start: { authorization_url: destination } }); const badURLUI = await open(badURL); await badURLUI.start.listeners.click();
    assert.equal(badURLUI.continue.hidden, true); assert.equal(badURLUI.continue.href, undefined); assert.equal(badURLUI.start.disabled, true);
  }

  const stale = setup(); let release; stale.pendingStatus = new Promise(resolve => { release = resolve; }); await ready(stale); const manage = find(stale.elements['connections-list'], e => e.dataset.connectionOauth2 === 'c1' && e.tagName === 'BUTTON'); const opening = manage.listeners.click(); await stale.statusRequested; const oldPanel = find(stale.elements['connections-list'], e => e.dataset.oauth2Panel === 'c1' && e.tagName === 'DIV'); await stale.context.accountDashboard.connections.loadDefinitions(); release(response({ state: 'draft', version: 0, connected: false, provider_id: '', scopes: [] })); await opening; assert.notEqual(find(stale.elements['connections-list'], e => e.dataset.oauth2Panel === 'c1' && e.tagName === 'DIV'), oldPanel);
  console.log('connection OAuth2 UI checks passed');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
