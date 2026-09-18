// Run the real browser functions with deterministic DOM/network boundaries.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(__dirname + '/admin.js', 'utf8');
const calls = [], elements = new Map(), timers = [];
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, {innerHTML: '', value: '', checked: false, textContent: '', append() {}});
    return elements.get(id);
  },
  querySelectorAll(selector) {
    return selector === '#key-form input[data-group]:checked'
      ? [{dataset: {group: 'Users', right: 'read'}}]
      : [];
  },
  querySelector(selector) {
    return selector === '#key-form button[type="submit"]' ? {disabled: false} : null;
  },
  createElement() {
    return {type: '', className: '', textContent: '', onclick: null};
  },
  addEventListener(_, fn) { this.listeners = this.listeners || []; this.listeners.push(fn); this.click = async ev => { for (const listener of this.listeners) await listener(ev); }; }
};
const replies = [{token: 'csrf'}, [{id: 'role/one', name: 'one', meta: null}]];
const ctx = {document, console, confirm: () => true, setTimeout: fn => timers.push(fn),
  failNext: false,
  pageHeaders: null,
  encodeURIComponent, decodeURIComponent, URLSearchParams, location: {pathname: '/auth/v1/admin/roles/role%2Fone'},
  fetch: async (url, opts = {}) => {
    calls.push({url, opts});
    if (ctx.failNext) {
      ctx.failNext = false;
      return {ok: false, status: 500, statusText: 'Server Error', headers: {get: () => 'application/json'}, json: async () => ({error: 'backend unavailable'})};
    }
    if (opts.method === 'POST' && url === '/auth/v1/api_keys')
      return {ok: true, headers: {get: () => 'text/plain'}, text: async () => 'managed-key$one-time-secret'};
    return {ok: true, headers: ctx.pageHeaders || {get: () => null}, json: async () => replies.shift() || {}};
  }};
const ready = vm.runInNewContext(source, ctx);
(async () => {
  await ready; // The actual route promise, no wall-clock delay.
  assert.equal(calls[1].url, '/auth/v1/roles');
  assert.match(document.getElementById('app').innerHTML, /data-id="role\/one"/);
  await document.click({target: {id: 'delete', dataset: {kind: 'roles', id: 'role/one'}}});
  assert.equal(calls.at(-1).url, '/auth/v1/roles/role%2Fone');
  assert.equal(calls.at(-1).opts.method, 'DELETE');
  assert.equal(calls.at(-1).opts.headers['X-CSRF-Token'], 'csrf');

  const existing = {language: 'fr', user_expires: 2000000000, roles: [], groups: [],
    user_values: {preferred_username: 'retained', birthdate: '2000-01-02', phone: '+33123456789',
      street: 'Main', zip: '12345', city: 'Paris', country: 'FR', tz: 'Europe/Paris'}};
  ctx.userForm('member/one', existing);
  assert.equal(document.getElementById('language').value, 'fr');
  document.getElementById('email').value = 'member@example.test';
  document.getElementById('given').value = 'Given';
  document.getElementById('family').value = 'Family';
  document.getElementById('expiry').value = String(existing.user_expires);
  for (const key of ['birthdate', 'phone', 'street', 'zip', 'city', 'country', 'tz'])
    document.getElementById('value-' + key).value = existing.user_values[key];
  await document.getElementById('user').onsubmit({preventDefault() {}});
  let payload = JSON.parse(calls.at(-1).opts.body);
  assert.equal(calls.at(-1).url, '/auth/v1/users/member%2Fone');
  assert.equal(payload.user_expires, existing.user_expires);
  assert.equal(payload.language, 'fr');
  assert.deepEqual(payload.roles, []);
  const {preferred_username, ...accepted} = existing.user_values;
  assert.deepEqual(payload.user_values, accepted);
  assert.equal(existing.user_values.preferred_username, 'retained');

  const callsBeforeInvalidExpiry = calls.length;
  ctx.userForm('member/one', existing);
  document.getElementById('expiry').value = '-1';
  await document.getElementById('user').onsubmit({preventDefault() {}});
  assert.equal(calls.length, callsBeforeInvalidExpiry);
  assert.match(document.getElementById('result').textContent, /non-negative safe integer/);

  ctx.userForm();
  document.getElementById('language').value = 'en';
  document.getElementById('expiry').value = '2000000000';
  document.getElementById('preferred').value = 'new-member';
  document.getElementById('timezone').value = 'Asia/Seoul';
  await document.getElementById('user').onsubmit({preventDefault() {}});
  payload = JSON.parse(calls.at(-1).opts.body);
  assert.equal(calls.at(-1).opts.method, 'POST');
  assert.equal(calls.at(-1).url, '/auth/v1/users');
  assert.equal('user_values' in payload, false);
  assert.deepEqual(payload.roles, []);

  assert.equal(payload.preferred_username, 'new-member');
  assert.equal(payload.tz, 'Asia/Seoul');
  assert.equal(payload.user_expires, 2000000000);
  document.getElementById('expiry').value = '';
  document.getElementById('preferred').value = '';
  document.getElementById('timezone').value = '';
  await document.getElementById('user').onsubmit({preventDefault() {}});
  payload = JSON.parse(calls.at(-1).opts.body);
  assert.equal(payload.user_expires, null);
  assert.equal('preferred_username' in payload, false);
  assert.equal('tz' in payload, false);

  ctx.apiKeyForm({name: 'managed-key', expires: 2000000000,
    access: [{group: 'Users', access_rights: ['read']}]});
  document.getElementById('key-name').value = 'managed-key';
  document.getElementById('key-expiry').value = '2000000000';
  await document.getElementById('key-form').onsubmit({preventDefault() {}});
  payload = JSON.parse(calls.at(-1).opts.body);
  assert.equal(calls.at(-1).url, '/auth/v1/api_keys/managed-key');
  assert.equal(calls.at(-1).opts.method, 'PUT');
  assert.equal(payload.name, 'managed-key');
  assert.deepEqual(payload.access, [{group: 'Users', access_rights: ['read']}]);
  assert.equal('secret' in payload, false);
  ctx.apiKeyForm();
  document.getElementById('key-name').value = 'created-key';
  document.getElementById('key-expiry').value = '';
  await document.getElementById('key-form').onsubmit({preventDefault() {}});
  assert.equal(document.getElementById('result').textContent, 'Secret (copy now): managed-key$one-time-secret');
  ctx.failNext = true;
  await document.click({target: {dataset: {rotate: 'managed-key'}}});
  assert.equal(document.getElementById('secret').textContent, 'backend unavailable');
  ctx.pageHeaders = {get: name => ({'X-User-Count': '2001', 'X-Page-Size': '1000', 'X-Page-Count': '3', 'X-Continuation-Token': 'cursor-2'}[name] || null)};
  ctx.location.pathname = '/auth/v1/admin/users';
  ctx.location.search = '';
  await ctx.users();
  assert.match(document.getElementById('table').innerHTML, /continuation_token=cursor-2/);
  console.log('admin UI behavioral checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
