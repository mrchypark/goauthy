// Run the real browser functions with deterministic DOM/network boundaries.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(__dirname + '/admin.js', 'utf8');
const calls = [], elements = new Map(), timers = [];
const koreanPermissionLabels = {Blacklist: 'IP 차단 목록', Clients: '클라이언트', Events: '이벤트', Generic: '일반',
  Groups: '그룹', Roles: '역할', Secrets: '비밀 값', Sessions: '세션', Scopes: '범위', UserAttributes: '사용자 속성',
  Users: '사용자', Pam: 'PAM', AuthProviders: '인증 공급자', ApiKeys: 'API 키',
  read: '읽기', create: '만들기', update: '수정', delete: '삭제',
  'API-key permissions do not grant API-key management. Manage keys with an administrator browser session.': 'API 키 권한으로는 API 키를 관리할 수 없습니다. 관리자 브라우저 세션으로 관리하세요.',
  'Request outcome is unknown. Check the current state before retrying.': '요청 결과를 확인할 수 없습니다. 다시 시도하기 전에 현재 상태를 확인하세요.'};
let checkedKeyRights = [{dataset: {group: 'Users', right: 'read'}}];
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, {innerHTML: '', value: '', checked: false, textContent: '', append() {}});
    return elements.get(id);
  },
  querySelectorAll(selector) {
    return selector === '#key-form input[data-group]:checked'
      ? checkedKeyRights
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
const ctx = {document, console, FormData, confirm: () => true, setTimeout: fn => timers.push(fn),
  GoAuthyI18n: {t(key, params = {}) { return (koreanPermissionLabels[key] || key).replace(/\{(\w+)\}/g, (_, name) => params[name] ?? `{${name}}`); }, setBusy() {}},
  failNext: false, failText: false, failFetchNext: false, failBodyNext: false, holdNext: false, groupRows: [], keyRows: [],
  pageHeaders: null,
  encodeURIComponent, decodeURIComponent, URLSearchParams, location: {pathname: '/auth/v1/admin/roles/role%2Fone'},
  fetch: async (url, opts = {}) => {
    calls.push({url, opts});
    if (ctx.failFetchNext) {
      ctx.failFetchNext = false;
      throw Error('Failed to fetch');
    }
    if (ctx.failNext) {
      ctx.failNext = false;
      if (ctx.failText) {
        ctx.failText = false;
        return {ok: false, status: 400, statusText: 'Bad Request', headers: {get: () => 'text/plain'}, text: async () => 'Invalid request\n'};
      }
      return {ok: false, status: 500, statusText: 'Server Error', headers: {get: () => 'application/json'}, json: async () => ({error: 'backend unavailable'})};
    }
    if (url === '/auth/v1/groups' && !opts.method)
      return {ok: true, headers: {get: () => null}, json: async () => ctx.groupRows};
    if (url.startsWith('/auth/v1/groups') && ['POST', 'PUT'].includes(opts.method)) {
      const payload = JSON.parse(opts.body);
      if (opts.method === 'POST') ctx.groupRows = [{id: 'group-one', name: payload.group, meta: payload.meta}];
      else ctx.groupRows = [{id: 'group-one', name: payload.group, meta: payload.meta}];
      if (ctx.failBodyNext) {
        ctx.failBodyNext = false;
        return {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => { throw Error('body stream failed'); }};
      }
      if (ctx.holdNext) {
        ctx.holdNext = false;
        return new Promise(resolve => { ctx.releaseNext = resolve; });
      }
      return {ok: true, headers: {get: () => 'application/json'}, json: async () => ctx.groupRows[0]};
    }
    if (url === '/auth/v1/api_keys' && !opts.method)
      return {ok: true, headers: {get: () => 'application/json'}, json: async () => ({keys: ctx.keyRows})};
    if (opts.method === 'POST' && url === '/auth/v1/api_keys')
      return {ok: true, headers: {get: () => 'text/plain'}, text: async () => 'managed-key$one-time-secret'};
    if (opts.method === 'PUT' && url.endsWith('/secret') && ctx.failBodyNext) {
      ctx.failBodyNext = false;
      return {ok: true, status: 200, headers: {get: () => 'text/plain'}, text: async () => { throw Error('body stream failed'); }};
    }
    if (opts.method === 'PUT' && url.endsWith('/secret'))
      return {ok: true, headers: {get: () => 'text/plain'}, text: async () => 'managed-key$rotated-secret'};
    if (opts.method === 'PUT' && url === '/auth/v1/theme/client-a')
      return {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => { throw Error('theme PUT has no body'); }};
    if (opts.method === 'DELETE' && url.startsWith('/auth/v1/api_keys/')) {
      ctx.keyRows = [];
      return {ok: true, status: 200, headers: {get: () => null}, json: async () => { throw Error('empty delete body'); }};
    }
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

  await ctx.entities('groups');
  assert.match(document.getElementById('app').innerHTML, /Manage groups through the live authorization service\./);
  assert.match(document.getElementById('app').innerHTML, />New group<\/a>/);
  assert.equal(document.getElementById('status').textContent, '0 groups');
  ctx.entityForm('groups');
  document.getElementById('name').value = 'staff';
  const callsBeforeInvalidMetadata = calls.length;
  for (const invalid of ['{invalid']) {
    document.getElementById('meta').value = invalid;
    const submitter = {disabled: false};
    await document.getElementById('entity').onsubmit({submitter, preventDefault() {}});
    assert.equal(calls.length, callsBeforeInvalidMetadata, `metadata ${invalid} reached the API`);
    assert.equal(submitter.disabled, false);
    assert.equal(document.getElementById('result').textContent, 'Metadata must be valid JSON');
  }
  for (const valid of ['[]', 'false', '0', '"label"', 'null']) {
    document.getElementById('meta').value = valid;
    await document.getElementById('entity').onsubmit({preventDefault() {}});
    assert.deepEqual(JSON.parse(calls.at(-1).opts.body), {group: 'staff', meta: JSON.parse(valid)});
  }
  document.getElementById('meta').value = '{"source":"admin"}';
  const groupSubmitter = {disabled: false};
  await document.getElementById('entity').onsubmit({submitter: groupSubmitter, preventDefault() {}});
  let payload = JSON.parse(calls.at(-1).opts.body);
  assert.equal(calls.at(-1).url, '/auth/v1/groups');
  assert.equal(calls.at(-1).opts.method, 'POST');
  assert.equal(calls.at(-1).opts.headers['X-CSRF-Token'], 'csrf');
  assert.deepEqual(payload, {group: 'staff', meta: {source: 'admin'}});
  assert.equal(groupSubmitter.disabled, true);
  await ctx.entities('groups');
  assert.match(document.getElementById('table').innerHTML, /href="\/auth\/v1\/admin\/groups\/group-one"/);
  ctx.groupRows[0].meta = false;
  ctx.entityForm('groups', 'group-one', ctx.groupRows);
  assert.match(document.getElementById('app').innerHTML, /<textarea id="meta" placeholder="\{ \}">false<\/textarea>/);
  document.getElementById('name').value = 'operators';
  document.getElementById('meta').value = '{"source":"reviewed"}';
  ctx.holdNext = true;
  const updateSubmitter = {disabled: false};
  const updatePending = document.getElementById('entity').onsubmit({submitter: updateSubmitter, preventDefault() {}});
  assert.equal(updateSubmitter.disabled, true);
  assert.equal(document.getElementById('result').textContent, 'Saving…');
  payload = JSON.parse(calls.at(-1).opts.body);
  assert.equal(calls.at(-1).url, '/auth/v1/groups/group-one');
  assert.equal(calls.at(-1).opts.method, 'PUT');
  assert.deepEqual(payload, {group: 'operators', meta: {source: 'reviewed'}});
  ctx.releaseNext({ok: true, headers: {get: () => 'application/json'}, json: async () => ctx.groupRows[0]});
  await updatePending;
  await ctx.entities('groups');
  assert.match(document.getElementById('table').innerHTML, />operators<\/a>/);

  ctx.failNext = true;
  ctx.failText = true;
  await ctx.entities('groups');
  assert.match(document.getElementById('table').innerHTML, /Could not load 그룹: Invalid request/);
  ctx.failFetchNext = true;
  await ctx.entities('groups');
  assert.match(document.getElementById('table').innerHTML, /Could not load 그룹: Failed to fetch/);
  ctx.entityForm('groups');
  document.getElementById('name').value = 'uncertain';
  const callsBeforeUnknownOutcome = calls.length, uncertainSubmitter = {disabled: false};
  ctx.failFetchNext = true;
  await document.getElementById('entity').onsubmit({submitter: uncertainSubmitter, preventDefault() {}});
  assert.equal(calls.length, callsBeforeUnknownOutcome + 1);
  assert.equal(calls.at(-1).url, '/auth/v1/groups');
  assert.equal(calls.at(-1).opts.method, 'POST');
  assert.equal(document.getElementById('result').textContent,
    '요청 결과를 확인할 수 없습니다. 다시 시도하기 전에 현재 상태를 확인하세요.');
  assert.equal(uncertainSubmitter.disabled, false);

  ctx.entityForm('groups');
  document.getElementById('name').value = 'body-unavailable';
  const callsBeforeUnreadableResponse = calls.length, unreadableSubmitter = {disabled: false};
  ctx.failBodyNext = true;
  await document.getElementById('entity').onsubmit({submitter: unreadableSubmitter, preventDefault() {}});
  assert.equal(calls.length, callsBeforeUnreadableResponse + 1);
  assert.equal(calls.at(-1).url, '/auth/v1/groups');
  assert.equal(calls.at(-1).opts.method, 'POST');
  assert.equal(document.getElementById('result').textContent,
    '요청 결과를 확인할 수 없습니다. 다시 시도하기 전에 현재 상태를 확인하세요.');
  assert.equal(unreadableSubmitter.disabled, false);

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
  payload = JSON.parse(calls.at(-1).opts.body);
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
  assert.match(document.getElementById('result').textContent, /at least 1719784800/);
  document.getElementById('expiry').value = '1719784799';
  await document.getElementById('user').onsubmit({preventDefault() {}});
  assert.equal(calls.length, callsBeforeInvalidExpiry);

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
  ctx.keyRows = [{name: 'managed-key', expires: 2000000000, access: [{group: 'Users', access_rights: ['read']}]}];
  await ctx.apiKeys();
  assert.equal(document.getElementById('status').textContent, '1 keys');
  assert.match(document.getElementById('table').innerHTML, /data-rotate="managed-key"/);
  checkedKeyRights = [{dataset: {group: 'ApiKeys', right: 'read'}}];
  ctx.apiKeyForm({access: [{group: 'ApiKeys', access_rights: ['read']}]});
  const keyFormMarkup = document.getElementById('app').innerHTML;
  assert.match(keyFormMarkup, /<legend>사용자 속성<\/legend>/);
  assert.match(keyFormMarkup, /<legend>API 키<\/legend>/);
  assert.match(keyFormMarkup, /data-group="ApiKeys" data-right="read" checked>읽기<\/label>/);
  assert.match(keyFormMarkup, /API 키 권한으로는 API 키를 관리할 수 없습니다\. 관리자 브라우저 세션으로 관리하세요\./);
  document.getElementById('key-name').value = 'created-key';
  document.getElementById('key-expiry').value = '';
  const callsBeforeOldKeyExpiry = calls.length;
  document.getElementById('key-expiry').value = '1719784799';
  await document.getElementById('key-form').onsubmit({preventDefault() {}});
  assert.equal(calls.length, callsBeforeOldKeyExpiry);
  assert.match(document.getElementById('result').textContent, /at least 1719784800/);
  document.getElementById('key-expiry').value = '';
  const createKeySubmitter = {disabled: false};
  await document.getElementById('key-form').onsubmit({submitter: createKeySubmitter, preventDefault() {}});
  assert.deepEqual(JSON.parse(calls.at(-1).opts.body).access, [{group: 'ApiKeys', access_rights: ['read']}]);
  assert.equal(document.getElementById('result').textContent, 'Secret (copy now): managed-key$one-time-secret');
  assert.equal(createKeySubmitter.disabled, true);
  const rotateButton = {disabled: false, dataset: {rotate: 'managed-key'}};
  await document.click({target: rotateButton});
  assert.equal(calls.at(-1).url, '/auth/v1/api_keys/managed-key/secret');
  assert.equal(calls.at(-1).opts.method, 'PUT');
  assert.equal(calls.at(-1).opts.headers['X-CSRF-Token'], 'csrf');
  assert.equal(document.getElementById('secret').textContent, 'Rotated secret (copy now): managed-key$rotated-secret');
  assert.equal(rotateButton.disabled, false);
  ctx.failNext = true;
  const failedRotateButton = {disabled: false, dataset: {rotate: 'managed-key'}};
  await document.click({target: failedRotateButton});
  assert.equal(document.getElementById('secret').textContent, 'backend unavailable');
  assert.equal(failedRotateButton.disabled, false);
  const unreadableRotateButton = {disabled: false, dataset: {rotate: 'managed-key'}}, callsBeforeUnreadableSecret = calls.length;
  ctx.failBodyNext = true;
  await document.click({target: unreadableRotateButton});
  assert.equal(calls.length, callsBeforeUnreadableSecret + 1);
  assert.equal(calls.at(-1).url, '/auth/v1/api_keys/managed-key/secret');
  assert.equal(calls.at(-1).opts.method, 'PUT');
  assert.equal(document.getElementById('secret').textContent,
    '요청 결과를 확인할 수 없습니다. 다시 시도하기 전에 현재 상태를 확인하세요.');
  assert.equal(unreadableRotateButton.disabled, false);
  const emptyThemeResult = await ctx.api('/auth/v1/theme/client-a', {method: 'PUT', responseType: 'empty', body: '{}'});
  assert.equal(emptyThemeResult, null);
  assert.equal(calls.at(-1).url, '/auth/v1/theme/client-a');
  assert.equal(calls.at(-1).opts.method, 'PUT');
  assert.equal('responseType' in calls.at(-1).opts, false);
  const upload = new FormData(); upload.append('file', 'test');
  await ctx.api('/auth/v1/clients/client-a/logo', {method:'PUT', body:upload, responseType:'empty'});
  assert.equal(calls.at(-1).opts.body, upload);
  assert.equal('Content-Type' in calls.at(-1).opts.headers, false);
  assert.equal(calls.at(-1).opts.headers['X-CSRF-Token'], 'csrf');
  const deleteKeyButton = {disabled: false, dataset: {remove: 'managed-key'}};
  await document.click({target: deleteKeyButton});
  assert.equal(calls.at(-2).url, '/auth/v1/api_keys/managed-key');
  assert.equal(calls.at(-2).opts.method, 'DELETE');
  assert.equal(calls.at(-2).opts.headers['X-CSRF-Token'], 'csrf');
  assert.match(document.getElementById('table').innerHTML, /No API keys\./);
  ctx.pageHeaders = {get: name => ({'X-User-Count': '2001', 'X-Page-Size': '1000', 'X-Page-Count': '3', 'X-Continuation-Token': 'cursor-2'}[name] || null)};
  ctx.location.pathname = '/auth/v1/admin/users';
  ctx.location.search = '';
  await ctx.users();
  assert.match(document.getElementById('table').innerHTML, /continuation_token=cursor-2/);
  vm.runInNewContext(fs.readFileSync(__dirname + '/providers.js', 'utf8'), ctx);
  ctx.providerForm('', {kind: 'api_key'});
  assert.match(document.getElementById('app').innerHTML, /id="prov-oauth-fields" hidden>/);
  document.getElementById('prov-kind').value = 'oauth2';
  document.getElementById('prov-kind').onchange();
  assert.equal(document.getElementById('prov-oauth-fields').hidden, false);
  document.getElementById('prov-kind').value = 'api_key';
  document.getElementById('prov-kind').onchange();
  assert.equal(document.getElementById('prov-oauth-fields').hidden, true);
  vm.runInNewContext(fs.readFileSync(__dirname + '/dashboard.js', 'utf8'), ctx);
  const beforeDashboard = calls.length;
  replies.push({email: 'admin@example.test', subject: 'admin'});
  await ctx.dashboard();
  assert.deepEqual(calls.slice(beforeDashboard).map(c => c.url), ['/account/data']);
  assert.equal(document.getElementById('overview-identity').textContent, 'admin@example.test');
  assert.match(document.getElementById('app').innerHTML, /href="\/account"/);
  assert.doesNotMatch(document.getElementById('app').innerHTML, /self-delete|profile-form/);
  ctx.failNext = true;
  await ctx.dashboard();
  assert.equal(document.getElementById('overview-identity').textContent,
    'Account details are unavailable. You can still choose a management area.');
  let themedClient;
  ctx.clientTheme = async id => { themedClient = id; };
  ctx.location.pathname = '/auth/v1/admin/clients/client-a/theme';
  await ctx.route();
  assert.equal(themedClient, 'client-a');
  console.log('admin UI behavioral checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
