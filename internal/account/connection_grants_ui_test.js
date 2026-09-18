const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(tag = 'DIV') { this.tagName = tag; this.children = []; this.dataset = {}; this.listeners = {}; this.hidden = false; this.disabled = false; this.value = ''; this.checked = false; this.textContent = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text; }
  set innerHTML(_) { throw new Error('unsafe HTML'); }
  append(...items) { this.children.push(...items); }
  insertBefore(item, before) { const index = this.children.indexOf(before); if (before !== null && index < 0) throw new Error('insertBefore reference is not a child'); this.children.splice(index < 0 ? this.children.length : index, 0, item); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute() {}
  querySelectorAll(selector) { const out = []; const tags = selector.split(',').map(s => s.toUpperCase()); const walk = (el) => { for (const child of el.children) { if (tags.includes(child.tagName) || selector === '[data-grant-review]' && child.dataset.grantReview !== undefined || selector === '[data-grant-refresh]' && child.dataset.grantRefresh !== undefined) out.push(child); walk(child); } }; walk(this); return out; }
}
const response = (body, status = 200) => ({ status, ok: status >= 200 && status < 300, text: async () => JSON.stringify(body) });
const find = (el, predicate) => { if (predicate(el)) return el; for (const child of el.children) { const found = find(child, predicate); if (found) return found; } return null; };

const now = 1700000000000;
const info = { id: 'provider', digest: 'D'.repeat(43), header: 'X-Key', prefix: '<b>not HTML</b>', operations: [{ id: 'read', method: 'GET', url: 'https://provider.test', response_fields: { ok: 'boolean' } }] };
function setup(options = {}) {
  const env = { calls: [], grants: [], current: true, busy: false, failPost: false, failRead: false, failConnector: false, pendingConnector: null, confirm: true, oauth: options.oauth };
  let requested; env.connectorRequested = new Promise(resolve => { requested = resolve; });
  const request = async (url, options = {}) => {
    env.calls.push({ url, options });
    if (url.endsWith('/connector')) { requested(); if (env.failConnector) throw new Error('private error'); return env.pendingConnector || response(info); }
    if (url.endsWith('/oauth2')) return typeof env.oauth === 'function' ? env.oauth() : response(env.oauth);
    if (options.method === 'POST') {
      if (env.failPost) throw new Error('Request failed (409). private error');
      env.grants = [{ ...JSON.parse(options.body), id: 'g1', revision: 1, resource: 'https://resource.test', revoked: false }]; return response(env.grants[0], 201);
    }
    if (options.method === 'DELETE') { env.grants[0].revoked = true; return response(null, 204); }
    if (env.failRead) throw new Error('private read error');
    return response(env.grants);
  };
  const context = { console, TextEncoder, Date: class extends Date { static now() { return now; } }, confirm: () => env.confirm, document: { createElement: tag => new Element(tag.toUpperCase()) }, accountDashboard: { state: { csrf: 'csrf' }, connectionDeps: {} } };
  vm.runInNewContext(fs.readFileSync(__dirname + '/connection_grants.js', 'utf8'), context);
  env.control = context.accountDashboard.connectionGrantControl({ connection: { id: 'conn' }, definition: options.definition || { enabled: true, auth_method: 'api_key', provider_ids: ['provider'] }, collection: 'keys', current: () => env.current, busy: () => env.busy, request, readJSON: async r => JSON.parse(await r.text()) });
  env.el = name => find(env.control, el => el.dataset[name] === 'conn');
  env.open = () => env.el('connectionGrants').listeners.click();
  env.fill = () => { env.el('grantConsumer').value = 'client'; env.el('grantPurpose').value = 'test'; const date = new Date(now + 3600000); date.setMinutes(date.getMinutes() - date.getTimezoneOffset()); env.el('grantExpiry').value = date.toISOString().slice(0,16); };
  env.approve = () => { env.el('grantReview').checked = true; env.el('grantReview').listeners.change(); };
  return env;
}
async function run() {
  const env = setup(); await env.open(); env.fill();
  assert.equal(env.el('grantCreate').disabled, true); await env.el('grantCreate').listeners.click(); assert.equal(env.calls.some(c => c.options.method === 'POST'), false);
  for (const name of ['grantConsumer', 'grantPurpose', 'grantExpiry']) { env.approve(); assert.equal(env.el('grantCreate').disabled, false); env.el(name).listeners.input(); assert.equal(env.el('grantReview').checked, false); assert.equal(env.el('grantCreate').disabled, true); }
  const expires = new Date(env.el('grantExpiry').value).getTime(); env.approve(); await env.el('grantCreate').listeners.click();
  const post = env.calls.find(c => c.options.method === 'POST'); assert.deepEqual(JSON.parse(post.options.body), { consumer_client_id: 'client', mode: 'proxy', purpose: 'test', expires_at_unix_ms: expires, connector_digest: info.digest }); assert.equal(post.options.headers['X-CSRF-Token'], 'csrf');
  assert.equal(env.el('grantReview').checked, false); assert.equal(env.el('grantConsumer').value, ''); assert.equal(env.el('grantCreate').disabled, true);
  const revoke = find(env.control, el => el.dataset.grantRevoke === 'g1'); env.confirm = false; await revoke.listeners.click(); assert.equal(env.calls.some(c => c.options.method === 'DELETE'), false); env.confirm = true; await revoke.listeners.click();
  const deletion = env.calls.find(c => c.options.method === 'DELETE'); assert.equal(deletion.options.headers['If-Match'], '"1"'); assert.equal(deletion.options.headers['X-CSRF-Token'], 'csrf'); assert.equal(find(env.control, el => el.dataset.grantRevoke === 'g1'), null);
  env.el('grantClose').listeners.click(); await env.open(); assert.equal(env.el('grantReview').checked, false); assert.equal(env.el('grantCreate').disabled, true);
  const failed = setup(); await failed.open(); failed.fill(); failed.approve(); failed.failPost = true; await failed.el('grantCreate').listeners.click(); assert.equal(failed.el('grantReview').checked, false); assert.equal(failed.el('grantCreate').disabled, true); assert.doesNotMatch(failed.el('grantStatus').textContent, /private/);
  for (const failure of ['failConnector', 'failRead']) { const bad = setup(); bad[failure] = true; await bad.open(); bad.fill(); bad.approve(); await bad.el('grantCreate').listeners.click(); assert.equal(bad.calls.some(c => c.options.method === 'POST'), false); assert.equal(bad.el('grantCreate').disabled, true); }
  const stale = setup(); let release; stale.pendingConnector = new Promise(resolve => { release = resolve; }); const opening = stale.open(); await stale.connectorRequested; stale.current = false; release(response(info)); await opening; stale.fill(); stale.approve(); const count = stale.calls.length; await stale.el('grantCreate').listeners.click(); assert.equal(stale.calls.length, count);
  const busy = setup(); await busy.open(); busy.fill(); busy.approve(); busy.busy = true; const prior = busy.calls.length; await busy.el('grantCreate').listeners.click(); assert.equal(busy.calls.length, prior);
  const oauth = setup({ oauth: { connected: true, state: 'ready', version: 7, account_id: '<img src=x onerror=alert(1)>', provider_id: 'provider', scopes: ['read', 'write'] }, definition: { enabled: true, auth_method: 'oauth2', provider_ids: ['provider', 'other'] } });
  await oauth.open(); oauth.fill(); const oauthSettings = find(oauth.control, el => el.tagName === 'P' && el.textContent.includes('Granted scopes:')); assert.match(oauthSettings.textContent, /<img src=x onerror=alert\(1\)>/); assert.match(oauthSettings.textContent, /read\nwrite/); assert.match(find(oauth.control, el => el.tagName === 'P' && el.textContent.startsWith('Warning:')).textContent, /access token.*all granted scopes/i); assert.equal(oauth.el('grantRefresh').checked, false); assert.equal(oauth.el('grantReview').checked, false); assert.equal(oauth.el('grantCreate').disabled, true); assert.equal(oauth.calls.filter(c => c.options.method === 'POST').length, 0); oauth.approve(); oauth.el('grantRefresh').checked = true; oauth.el('grantRefresh').listeners.change(); assert.equal(oauth.el('grantReview').checked, false); oauth.approve(); const oauthExpires = new Date(oauth.el('grantExpiry').value).getTime(); await oauth.el('grantCreate').listeners.click();
  const oauthPost = oauth.calls.find(c => c.options.method === 'POST'); assert.deepEqual(JSON.parse(oauthPost.options.body), { consumer_client_id: 'client', mode: 'credential_delivery', purpose: 'test', expires_at_unix_ms: oauthExpires, credential_version: 7, allow_refresh: true }); assert.equal(oauth.el('grantRefresh').checked, false); assert.equal(oauth.el('grantReview').checked, false);
  const oauthDefinition = { enabled: true, auth_method: 'oauth2', provider_ids: ['provider'] };
  for (const badMetadata of [
    { connected: false, state: 'ready', version: 1, account_id: 'a', provider_id: 'provider', scopes: ['read'] },
    { connected: true, state: 'revoked', version: 1, account_id: 'a', provider_id: 'provider', scopes: ['read'] },
    { connected: true, state: 'ready', version: 0, account_id: 'a', provider_id: 'provider', scopes: ['read'] },
    { connected: true, state: 'ready', version: 1.5, account_id: 'a', provider_id: 'provider', scopes: ['read'] },
    { connected: true, state: 'ready', version: Number.MAX_SAFE_INTEGER + 1, account_id: 'a', provider_id: 'provider', scopes: ['read'] },
    { connected: true, state: 'ready', version: 1, account_id: '', provider_id: 'provider', scopes: ['read'] },
    { connected: true, state: 'ready', version: 1, account_id: 'a', provider_id: 'other', scopes: ['read'] },
    { connected: true, state: 'ready', version: 1, account_id: 'a', provider_id: 'provider', scopes: ['read write'] },
  ]) {
    const bad = setup({ oauth: badMetadata, definition: oauthDefinition }); await bad.open(); bad.fill(); bad.approve(); await bad.el('grantCreate').listeners.click();
    assert.equal(bad.calls.filter(c => c.options.method === 'POST').length, 0); assert.equal(bad.el('grantCreate').disabled, true);
  }
  let resolveOAuth; const staleOAuth = setup({ definition: oauthDefinition, oauth: () => new Promise(resolve => { resolveOAuth = resolve; }) }); const staleOAuthOpen = staleOAuth.open(); await new Promise(resolve => setImmediate(resolve)); staleOAuth.current = false; resolveOAuth(response({ connected: true, state: 'ready', version: 2, account_id: 'a', provider_id: 'provider', scopes: ['read'] })); await staleOAuthOpen; assert.equal(staleOAuth.el('grantReview').checked, false); assert.equal(staleOAuth.el('grantCreate').disabled, true); assert.equal(staleOAuth.calls.filter(c => c.options.method === 'POST').length, 0);
  const conflict = setup({ oauth: { connected: true, state: 'ready', version: 7, account_id: 'a', provider_id: 'provider', scopes: ['read'] }, definition: oauthDefinition });
  await conflict.open(); conflict.fill(); conflict.approve(); conflict.failPost = true;
  await conflict.el('grantCreate').listeners.click();
  assert.equal(conflict.el('grantClose').disabled, false);
  assert.equal(conflict.el('grantReview').checked, false);
  assert.equal(conflict.el('grantPanel').hidden, false);
  assert.match(conflict.el('grantStatus').textContent, /Close and reopen/);
  assert.doesNotMatch(conflict.el('grantStatus').textContent, /private/);
  const beforeRetry = conflict.calls.filter(c => c.options.method === 'POST').length;
  conflict.fill(); conflict.approve(); await conflict.el('grantCreate').listeners.click();
  assert.equal(conflict.calls.filter(c => c.options.method === 'POST').length, beforeRetry);
  conflict.el('grantClose').listeners.click();
  assert.equal(conflict.el('grantPanel').hidden, true);
  conflict.failPost = false;
  conflict.oauth = { connected: true, state: 'ready', version: 8, account_id: 'a', provider_id: 'provider', scopes: ['read'] };
  await conflict.open();
  assert.equal(conflict.el('grantReview').checked, false);
  assert.equal(conflict.el('grantCreate').disabled, true);
  conflict.fill(); conflict.approve(); await conflict.el('grantCreate').listeners.click();
  const conflictPost = conflict.calls.filter(c => c.options.method === 'POST').at(-1);
  assert.equal(JSON.parse(conflictPost.options.body).credential_version, 8);
  console.log('connection grants UI checks passed');
}
run().catch((error) => { console.error(error); process.exitCode = 1; });
