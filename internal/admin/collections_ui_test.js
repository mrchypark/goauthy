const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(__dirname + '/collections.js', 'utf8');
const calls = [];
const elements = new Map();
const root = {innerHTML: ''};
function element(id) {
  if (!elements.has(id)) elements.set(id, {id, innerHTML: '', textContent: '', className: '', value: '', disabled: false, querySelectorAll: () => [], querySelector: () => null, addEventListener: () => {}});
  return elements.get(id);
}
const ctx = {
  console,
  document: {getElementById: element, querySelectorAll: () => []},
  root,
  esc: value => String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c])),
  split: value => value.split(',').map(x => x.trim()).filter(Boolean),
  shell: (_title, _sub, body) => { root.innerHTML = body; for (const match of body.matchAll(/(?:id|data-[a-z-]+)="([^"]+)"/g)) element(match[1]); },
  api: async (url, opts = {}) => { calls.push({url, opts}); if (url.includes('/missing')) throw Error('missing collection'); return opts.method ? {} : (url.endsWith('auth-collections') ? [{id: 'login', name: 'Login', auth_method: 'oauth2', enabled: true, revision: 3, fields: [], provider_ids: ['github', 'google']}] : {id: 'login', name: 'Login', auth_method: 'oauth2', enabled: true, revision: 3, fields: [], provider_ids: ['github', 'google']}); },
  confirm: message => { assert.match(message, /Delete collection/); return true; },
};
vm.createContext(ctx);
vm.runInContext(source, ctx, {filename: 'collections.js'});

(async () => {
  await ctx.collections();
  assert.match(root.innerHTML, /collection-status/);
  assert.match(element('collection-list').innerHTML, /Login/);
  await ctx.collections('missing');
  assert.match(element('collection-error').textContent || root.innerHTML, /missing collection/);
  await ctx.collections('new', 'new');
  element('collection-id').value = 'draft-one';
  element('collection-name').value = 'Draft one';
  element('collection-method').value = 'oauth2';
  element('collection-enabled').checked = true;
  const collectionFields = element('collection-fields');
  const enumOptions = ['  keep  ', 'line\nbreak'];
  const enumOptionsInput = {value: JSON.stringify(enumOptions)};
  const enumRow = {
    querySelector: selector => ({
      '[data-field-name]': {value: 'choice'},
      '[data-field-type]': {value: 'enum'},
      '[data-field-required]': {checked: false},
      '[data-field-max]': {value: ''},
      '[data-field-options]': enumOptionsInput,
    }[selector]),
  };
  collectionFields.querySelectorAll = selector => selector === '.collection-field' ? [enumRow] : [];
  await element('collection-form').onsubmit({preventDefault() {}});
  const created = calls.at(-2);
  assert.equal(created.url, '/auth/v1/auth-collections');
  assert.equal(created.opts.method, 'POST');
  const createdBody = JSON.parse(created.opts.body);
  assert.equal(createdBody.id, 'draft-one');
  assert.deepEqual(createdBody.fields[0].options, enumOptions);
  const writesBeforeMalformed = calls.filter(call => call.opts.method === 'POST' || call.opts.method === 'PUT').length;
  enumOptionsInput.value = '["unterminated"';
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.equal(calls.filter(call => call.opts.method === 'POST' || call.opts.method === 'PUT').length, writesBeforeMalformed);
  assert.match(element('collection-result').textContent, /Unexpected end|JSON/);
  collectionFields.querySelectorAll = () => [];
  await ctx.collections('login', 'edit');
  assert.equal(calls.at(-1).url, '/auth/v1/auth-collections/login');
  assert.match(root.innerHTML, /github\ngoogle/);
  assert.deepEqual([...ctx.providerIDs('1provider\nfoo-bar')], ['1provider', 'foo-bar']);
  element('collection-name').value = 'Login';
  element('collection-providers').value = 'github\ngoogle';
  await element('collection-form').onsubmit({preventDefault() {}});
  const updated = calls.at(-2);
  assert.equal(updated.url, '/auth/v1/auth-collections/login');
  assert.equal(updated.opts.method, 'PUT');
  assert.equal(updated.opts.headers['If-Match'], '"3"');
  assert.equal(updated.opts.body, '{"name":"Login","auth_method":"oauth2","enabled":true,"provider_ids":["github","google"],"fields":[]}');
  element('collection-providers').value = 'github\ngithub';
  const writesBeforeDuplicate = calls.filter(call => call.opts.method === 'PUT').length;
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.equal(calls.filter(call => call.opts.method === 'PUT').length, writesBeforeDuplicate);
  element('collection-providers').value = 'github';
  ctx.confirm = message => { assert.match(message, /permanently revokes/); return false; };
  const writesBeforeCancel = calls.filter(call => call.opts.method === 'PUT').length;
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.equal(calls.filter(call => call.opts.method === 'PUT').length, writesBeforeCancel);

  await ctx.collections('new', 'new');
  element('collection-id').value = 'api-provider';
  element('collection-name').value = 'API provider';
  element('collection-method').value = 'api_key';
  element('collection-providers').value = 'registered-api';
  element('collection-enabled').checked = true;
  const apiKeyWrites = calls.filter(call => call.opts.method === 'POST').length;
  await element('collection-form').onsubmit({preventDefault() {}});
  const apiKeyCreated = calls.at(-2);
  assert.equal(apiKeyCreated.opts.method, 'POST');
  assert.deepEqual(JSON.parse(apiKeyCreated.opts.body).provider_ids, ['registered-api']);
  assert.equal(calls.filter(call => call.opts.method === 'POST').length, apiKeyWrites + 1);
  element('collection-providers').value = 'first\nsecond';
  const writesBeforeTwoApiProviders = calls.filter(call => call.opts.method === 'POST').length;
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.equal(calls.filter(call => call.opts.method === 'POST').length, writesBeforeTwoApiProviders);
  assert.match(element('collection-result').textContent, /at most one/);
  element('collection-method').value = 'device_flow';
  element('collection-providers').value = 'device-provider';
  const writesBeforeDeviceProvider = calls.filter(call => call.opts.method === 'POST').length;
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.equal(calls.filter(call => call.opts.method === 'POST').length, writesBeforeDeviceProvider);
  assert.match(element('collection-result').textContent, /Device flow/);
  element('collection-method').value = 'api_key';
  element('collection-providers').value = '';
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.equal(calls.at(-2).opts.method, 'POST');
  assert.deepEqual(JSON.parse(calls.at(-2).opts.body).provider_ids, []);

  ctx.api = async (url, opts = {}) => {
    calls.push({url, opts});
    if (opts.method) return {};
    if (url.endsWith('/api-edit')) return {id: 'api-edit', name: 'API edit', auth_method: 'api_key', enabled: true, revision: 4, fields: [], provider_ids: ['registered-api']};
    return [];
  };
  await ctx.collections('api-edit', 'edit');
  element('collection-providers').value = '';
  ctx.confirm = message => { assert.match(message, /permanently revokes/); return false; };
  const writesBeforeApiRemovalCancel = calls.filter(call => call.opts.method === 'PUT').length;
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.equal(calls.filter(call => call.opts.method === 'PUT').length, writesBeforeApiRemovalCancel);
  assert.equal(element('collection-result').textContent, 'Save cancelled');
  assert.match(root.innerHTML, /encrypted legacy storage without a connector/);
  element('collection-providers').value = 'registered-api';
  ctx.confirm = () => true;
  await element('collection-form').onsubmit({preventDefault() {}});
  const apiKeyUpdated = calls.at(-2);
  assert.equal(apiKeyUpdated.opts.method, 'PUT');
  assert.deepEqual(JSON.parse(apiKeyUpdated.opts.body).provider_ids, ['registered-api']);

  ctx.api = async (url, opts = {}) => { calls.push({url, opts}); return opts.method ? {} : (url.endsWith('auth-collections') ? [{id: 'login', name: 'Login', auth_method: 'oauth2', enabled: true, revision: 3, fields: [], provider_ids: ['github', 'google']}] : {id: 'login', name: 'Login', auth_method: 'oauth2', enabled: true, revision: 3, fields: [], provider_ids: ['github', 'google']}); };
  await ctx.collections('login', 'edit');
  element('collection-method').value = 'oauth2';
  element('collection-name').value = 'Login';
  element('collection-providers').value = 'github\ngoogle';
  ctx.confirm = message => { assert.match(message, /Delete collection/); return true; };
  ctx.api = async (url, opts = {}) => { calls.push({url, opts}); throw Error('409 conflict'); };
  await element('collection-form').onsubmit({preventDefault() {}});
  assert.match(element('collection-result').textContent, /Reload the collection/);
  assert.equal(element('collection-name').value, 'Login');
  ctx.api = async (url, opts = {}) => { calls.push({url, opts}); return opts.method ? {} : {id: 'login', name: 'Login', auth_method: 'oauth2', enabled: true, revision: 3, fields: []}; };
  await element('collection-delete').onclick();
  const deleted = calls.at(-2);
  assert.equal(deleted.opts.method, 'DELETE');
  assert.equal(deleted.opts.headers['If-Match'], '"3"');
  assert.match(source, /If-Match/);
  assert.match(source, /metadata-only/);
  assert.match(source, /data-field-type/);

  let resolveSave;
  ctx.api = async (url, opts = {}) => { calls.push({url, opts}); if (opts.method === 'POST') return new Promise(resolve => { resolveSave = resolve; }); return []; };
  const postBefore = calls.filter(call => call.opts.method === 'POST' && call.url === '/auth/v1/auth-collections').length;
  await ctx.collections('new', 'new');
  element('collection-id').value = 'pending-one'; element('collection-name').value = 'Pending'; element('collection-method').value = 'oauth2'; element('collection-enabled').checked = true;
  const first = element('collection-form').onsubmit({preventDefault() {}});
  const second = element('collection-form').onsubmit({preventDefault() {}});
  await Promise.resolve();
  assert.equal(calls.filter(call => call.opts.method === 'POST' && call.url === '/auth/v1/auth-collections').length, postBefore + 1);
  resolveSave({}); await first; await second;
  console.log('collections UI behavioral checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
