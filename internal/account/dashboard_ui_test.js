const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, { id, value: '', textContent: '', className: '', hidden: true, dataset: {}, children: [], addEventListener() {}, append(...children) { this.children.push(...children); }, reset() {}, querySelector() { return { disabled: false }; }, querySelectorAll() { return []; } });
  return elements.get(id);
}
const form = (id) => Object.assign(element(id), { querySelectorAll() { return []; }, reset() {} });
const requests = [];
const responses = [
  { ok: true, json: async () => ({ subject: 'user/1', email: 'a@example.test', given_name: 'A', csrf_token: 'csrf' }) },
  { ok: true, json: async () => ({ values: [{ name: 'score', typ: 'number', value: 7 }, { name: 'enabled', typ: 'text', value: true }, { name: 'metadata', typ: 'text', value: { team: 'a' } }] }) },
  { ok: true, status: 202, json: async () => ({}) },
  { ok: true, json: async () => ({}) },
  { ok: true, json: async () => ({}) },
  { ok: true, json: async () => ({}) },
];
const context = {
  console,
  window: { location: { pathname: '/account' } },
  document: { querySelector(selector) { return element(selector[0] === '#' ? selector.slice(1) : selector); }, getElementById: element, createElement(tag) { return { tagName: tag, id: '', value: '', textContent: '', className: '', hidden: false, dataset: {}, htmlFor: '', append() {}, addEventListener() {} }; } },
  fetch: async (url, options) => { requests.push({ url, options }); return responses.shift(); },
};
context.globalThis = context;
vm.runInNewContext(fs.readFileSync(__dirname + '/dashboard.js', 'utf8'), context);

(async () => {
  await context.accountDashboard.ready;
  assert.equal(context.accountDashboard.state.account.subject, 'user/1');
  element('preferred-username').value = 'new-name';
  await context.accountDashboard.submitUsername({ preventDefault() {} });
  assert.equal(requests[3].url, '/auth/v1/users/user%2F1/self/preferred_username');
  assert.equal(requests[3].options.method, 'PUT');
  assert.equal(requests[3].options.headers['X-CSRF-Token'], 'csrf');
  assert.deepEqual(JSON.parse(requests[3].options.body), { preferred_username: 'new-name' });

  element('password-current').value = 'CurrentPassword1';
  element('password-new').value = 'NewPassword2';
  element('password-confirm').value = 'NewPassword2';
  const passwordForm = Object.assign(form('password-form'), { querySelector() { return { disabled: false }; } });
  await context.accountDashboard.submitPassword({ preventDefault() {}, target: passwordForm });
  assert.equal(requests[4].url, '/auth/v1/users/user%2F1/self');
  assert.equal(requests[4].options.method, 'PUT');
  assert.deepEqual(JSON.parse(requests[4].options.body), { password_current: 'CurrentPassword1', password_new: 'NewPassword2' });
  assert.match(element('password-status').textContent, /Password changed/);
  const attributeForm = { querySelectorAll() { return [{ dataset: { attribute: 'score' }, value: '8' }, { dataset: { attribute: 'enabled' }, value: 'false' }, { dataset: { attribute: 'metadata' }, value: '{"team":"b"}' }]; } };
  await context.accountDashboard.submitAttributes({ preventDefault() {}, target: attributeForm });
  assert.deepEqual(JSON.parse(requests[5].options.body), { values: [{ key: 'score', value: 8 }, { key: 'enabled', value: false }, { key: 'metadata', value: { team: 'b' } }] });
  element('passkey-name').value = '';
  const beforePasskey = requests.length;
  await context.accountDashboard.addPasskey({ preventDefault() {} });
  assert.equal(requests.length, beforePasskey, 'empty passkey names must not authorize');
  assert.match(element('passkey-status').textContent, /unavailable|name/i);
  const beforeCancel = requests.length;
  context.confirm = () => false;
  await context.accountDashboard.deletePasskey('existing');
  assert.equal(requests.length, beforeCancel, 'cancelled removal must not authorize');
  responses.push({ ok: true, json: async () => ({ subject: 'user/1', csrf_token: 'csrf' }) }, { ok: false, status: 503 });
  await context.accountDashboard.load();
  assert.equal(context.accountDashboard.state.attributesLoaded, false);
  assert.equal(element('attributes-form button').disabled, true);
  assert.match(element('attributes-status').textContent, /Unable to load editable details/);
  const before = requests.length;
  await context.accountDashboard.submitAttributes({ preventDefault() {}, target: attributeForm });
  assert.equal(requests.length, before, 'failed load must not send an empty successful save');
  assert.match(element('attributes-status').textContent, /Reload/);
  const json = value => ({ok: true, json: async () => value});
  const parsed = [];
  context.PublicKeyCredential = {
    parseCreationOptionsFromJSON(value) { assert.equal(this, context.PublicKeyCredential); assert.equal(value.challenge, 'creation'); parsed.push(value); return value; },
    parseRequestOptionsFromJSON(value) { assert.equal(this, context.PublicKeyCredential); assert.equal(value.challenge, 'assertion'); parsed.push(value); return value; },
  };
  const credential = {id: 'opaque', type: 'public-key', response: {clientDataJSON: 'encoded'}};
  context.navigator = {credentials: {
    create: async ({publicKey}) => { assert.equal(publicKey.challenge, 'creation'); return {toJSON: () => credential}; },
    get: async ({publicKey}) => { assert.equal(publicKey.challenge, 'assertion'); return {toJSON: () => credential}; },
  }};
  context.accountDashboard.state.passkeysLoaded = true;
  element('passkey-current-password').value = 'CurrentPassword1';
  element('passkey-name').value = 'first';
  const refreshed = () => json({subject:'user/1', email:'a@example.test', csrf_token:'csrf', features:{password:true, passkeys:true, passkey_conversion:true}});
  responses.push(json({id: 'mod-1'}), json({publicKey: {challenge: 'creation'}}), json({}), refreshed(), json([{name: 'first'}]));
  const first = requests.length;
  await context.accountDashboard.addPasskey({preventDefault() {}});
  assert.deepEqual(JSON.parse(requests[first].options.body), {password: 'CurrentPassword1'});
  assert.deepEqual(JSON.parse(requests[first+1].options.body), {passkey_name: 'first', mfa_mod_token_id: 'mod-1'});
  assert.deepEqual(JSON.parse(requests[first+2].options.body), {passkey_name: 'first', data: credential});
  assert.equal(requests[first+3].url, '/account/data', 'UV registration must refresh server-issued MFA capability');
  assert.equal(element('passwordless-convert').disabled, false);
  assert.equal(element('passkey-status').textContent, 'Passkey added.');
  assert.equal(element('passkey-current-password').value, '');
  element('passkey-name').value = 'second';
  const proof = () => [json({code: 'challenge-code', rcr: {publicKey: {challenge: 'assertion'}}}), json({code: 'proof-code'}), json({id: 'mod-2'})];
  responses.push(...proof(), json({publicKey: {challenge: 'creation'}}), json({}), refreshed(), json([{name: 'first'}, {name: 'second'}]));
  const second = requests.length;
  await context.accountDashboard.addPasskey({preventDefault() {}});
  assert.deepEqual(JSON.parse(requests[second].options.body), {purpose: 'MfaModToken'});
  assert.deepEqual(JSON.parse(requests[second+1].options.body), {code: 'challenge-code', data: credential});
  assert.deepEqual(JSON.parse(requests[second+2].options.body), {mfa_code: 'proof-code'});
  assert.equal(element('passkey-status').textContent, 'Passkey added.');
  context.confirm = () => true;
  responses.push(...proof(), json({}), json([{name: 'second'}]));
  const deletion = requests.length;
  await context.accountDashboard.deletePasskey('first');
  assert.equal(requests[deletion+3].url, '/auth/v1/users/user%2F1/webauthn/delete/first');
  assert.equal(requests[deletion+3].options.method, 'DELETE');
  assert.deepEqual(JSON.parse(requests[deletion+3].options.body), {mfa_mod_token_id: 'mod-2'});
  assert.equal(element('passkey-status').textContent, 'Passkey removed.');
  assert.equal(parsed.length, 4);
  responses.push({ok: false, status: 503});
  await assert.rejects(context.accountDashboard.loadPasskeys(), /Request failed/);
  assert.equal(element('passkey-add').disabled, true);
  const failedLoad = requests.length;
  await context.accountDashboard.deletePasskey('second');
  assert.equal(requests.length, failedLoad);
  context.accountDashboard.state.passkeysLoaded = true;
  context.accountDashboard.state.passkeys = [{name: 'second'}];
  context.accountDashboard.state.account.features = {password: true, passkeys: true, passkey_conversion: true};
  const beforeConversionCancel = requests.length;
  context.confirm = () => false;
  await context.accountDashboard.convertPasswordless();
  assert.equal(requests.length, beforeConversionCancel);
  context.confirm = () => true;
  responses.push({ok: false, status: 503});
  await context.accountDashboard.convertPasswordless();
  assert.equal(element('passwordless-convert').disabled, false, 'failed mutation must allow retry');
  assert.match(element('passwordless-status').textContent, /503/);
  responses.push(json({}), {ok: false, status: 503});
  await context.accountDashboard.convertPasswordless();
  assert.match(element('passwordless-status').textContent, /503/, 'failed refresh must not report success');
  responses.push(json({}), json({subject: 'user/1', email: 'a@example.test', csrf_token: 'csrf', features: {password: false, passkeys: true, passkey_conversion: false}}));
  const conversion = requests.length;
  await context.accountDashboard.convertPasswordless();
  assert.equal(requests[conversion].options.method, 'POST');
  assert.equal(requests[conversion].options.body, undefined, 'conversion must send an empty body');
  assert.equal(requests[conversion].options.headers['X-CSRF-Token'], 'csrf');
  context.accountDashboard.state.account.features = {password: false, passkeys: true};
  context.accountDashboard.state.passkeysLoaded = true;
  responses.push(json({code: 'restore-start', rcr: {publicKey: {challenge: 'assertion'}}}), json({code: 'restore-proof'}), json({}), json({subject: 'user/1', email: 'a@example.test', csrf_token: 'csrf', features: {password: true, passkeys: true}}));
  element('password-restore-new').value = 'RestoredPassword2'; element('password-restore-confirm').value = 'RestoredPassword2';
  const restore = requests.length;
  await context.accountDashboard.restorePassword({preventDefault() {}});
  assert.deepEqual(JSON.parse(requests[restore].options.body), {purpose: 'PasswordNew'});
  assert.deepEqual(JSON.parse(requests[restore+1].options.body), {code: 'restore-start', data: credential});
  assert.deepEqual(JSON.parse(requests[restore+2].options.body), {mfa_code: 'restore-proof', password_new: 'RestoredPassword2'});
  assert.equal(element('password-restore-new').value, '');
  context.accountDashboard.state.account.features.password = false;
  context.navigator.credentials.get = async () => null;
  responses.push(json({code: 'restore-cancel', rcr: {publicKey: {challenge: 'assertion'}}}));
  element('password-restore-new').value = 'CancelledPassword2'; element('password-restore-confirm').value = 'CancelledPassword2';
  const restoreCancelled = requests.length;
  await context.accountDashboard.restorePassword({preventDefault() {}});
  assert.equal(requests.length, restoreCancelled + 1);
  assert.match(element('password-restore-status').textContent, /cancelled/i);
  context.navigator.credentials.get = async ({publicKey}) => { assert.equal(publicKey.challenge, 'assertion'); return {toJSON: () => credential}; };
  for (const failure of [406, 503]) {
    responses.push({ok: false, status: failure});
    await context.accountDashboard.checkSelfDelete();
    assert.equal(context.accountDashboard.state.selfDeleteAllowed, false);
    assert.equal(element('self-delete-section').hidden, failure === 406);
    assert.equal(element('self-delete-button').disabled, true);
    element('self-delete-confirm').value = 'a@example.test';
    const forbiddenDelete = requests.length;
    await context.accountDashboard.deleteAccount();
    assert.equal(requests.length, forbiddenDelete, 'failed capability cannot delete');
  }
  responses.push({ok: true, status: 202});
  await context.accountDashboard.checkSelfDelete();
  assert.equal(context.accountDashboard.state.selfDeleteAllowed, true);
  context.confirm = () => false;
  const cancelledDelete = requests.length;
  await context.accountDashboard.deleteAccount();
  assert.equal(requests.length, cancelledDelete);
  context.confirm = () => true;
  responses.push({ok: true, status: 202});
  await context.accountDashboard.deleteAccount();
  assert.notEqual(context.accountDashboard.state.account, null, '202 is not completed deletion');
  assert.match(element('self-delete-status').textContent, /not completed/);
  context.accountDashboard.state.selfDeleteAllowed = true;
  element('self-delete-confirm').value = 'a@example.test';
  responses.push({ok: true, status: 204, json: async () => ({})});
  const deletionAccount = requests.length;
  await context.accountDashboard.deleteAccount();
  assert.equal(requests[deletionAccount].options.body, '');
  assert.ok(element('main').children.some((child) => child.id === 'account-deleted'));
  assert.equal(responses.length, 0);
  const afterDelete = requests.length;
  await context.accountDashboard.convertPasswordless();
  assert.equal(requests.length, afterDelete, 'terminal account must not fetch again');
  console.log('dashboard UI checks passed');
})().catch((error) => { console.error(error); process.exitCode = 1; });
