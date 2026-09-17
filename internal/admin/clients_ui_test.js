const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
const device = 'urn:ietf:params:oauth:grant-type:device_code';
const elements = new Map(), calls = [];
const decode = s => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const get = id => elements.get(id) || null;
const buttons = () => [...elements.values()].filter(e => e.tagName === 'BUTTON');
let current, handler;
const ctx = {
  console, location: {href: ''}, encodeURIComponent,
  esc: s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])),
  confirm: s => { assert.equal(s, 'Delete client c1 permanently?'); return true; },
  document: {getElementById: get, querySelectorAll(selector) {
    if (selector === '#client-form button') return buttons();
    if (selector === '[data-client-flow]') return [...elements.values()].filter(e => e.dataset.clientFlow);
    if (selector === '[data-client-flow]:checked') return [...elements.values()].filter(e => e.dataset.clientFlow && e.checked);
    throw Error('Unexpected selector: ' + selector);
  }},
  // Bounded form fixture, not a browser substitute: missing IDs return null,
  // rerender discards removed controls, and native input defaults survive.
  shell(_title, _hint, html) {
    elements.clear();
    for (const m of html.matchAll(/<(\w+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
      const attrs = m[2], tag = m[1].toUpperCase();
      const value = /\bvalue="([^"]*)"/.exec(attrs)?.[1] || '';
      const text = tag === 'TEXTAREA' ? html.slice(m.index + m[0].length).split('</textarea>')[0] : '';
      elements.set(m[3], {tagName: tag, value: decode(text || value), checked: /\schecked(?:\s|$)/.test(attrs), disabled: false,
        innerHTML: '', textContent: '', className: '', dataset: {clientFlow: /data-client-flow="([^"]+)"/.exec(attrs)?.[1]}});
    }
  },
  api: async (url, opts = {}) => { calls.push({url, opts}); return handler(url, opts); },
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(__dirname + '/clients.js', 'utf8'), ctx);
const submit = () => get('client-form').onsubmit({preventDefault() {}});
const fixture = confidential => ({id: 'c1', name: 'One', confidential, enabled: true, revision: 7,
  redirect_uris: ['https://app.example/cb?a=one,two'], scopes: ['goauthy.read', 'offline_access'],
  audience: ['https://resource.example/api/one,two'], default_scopes: ['goauthy.read'], enabled_flows: ['authorization_code', 'refresh_token', device]});
function normalAPI(_url, opts) {
  if (!opts.method) return {...current};
  if (opts.method === 'PUT') { current = {...current, ...JSON.parse(opts.body), revision: 11}; return {...current}; }
  return {revision: 1};
}
(async () => {
  current = fixture(false); handler = normalAPI;
  await ctx.clients('c1', 'edit');
  assert.equal(get('client-secret-hide'), null);
  await submit();
  const update = calls.find(c => c.opts.method === 'PUT');
  assert.equal(update.opts.headers['If-Match'], '"7"');
  assert.deepEqual(JSON.parse(update.opts.body).enabled_flows, current.enabled_flows);
  assert.deepEqual(JSON.parse(update.opts.body).redirect_uris, ['https://app.example/cb?a=one,two']);
  assert.deepEqual(JSON.parse(update.opts.body).audience, ['https://resource.example/api/one,two']);
  await submit();
  assert.equal(calls.filter(c => c.opts.method === 'PUT').at(-1).opts.headers['If-Match'], '"11"');
  await ctx.clients('new', 'new');
  get('client-device').onclick();
  assert.equal(get('client-confidential').checked, false);
  assert.equal(get('client-redirects').value, '');
  assert.deepEqual(ctx.document.querySelectorAll('[data-client-flow]:checked').map(e => e.dataset.clientFlow), ['refresh_token', device]);
  get('client-audience').value = 'https://resource.example/api/one,two';
  get('client-device').onclick();
  assert.equal(get('client-audience').value, 'https://resource.example/api/one,two');
  get('client-web').onclick();
  assert.deepEqual(ctx.document.querySelectorAll('[data-client-flow]:checked').map(e => e.dataset.clientFlow), ['authorization_code', 'refresh_token']);
  assert.match(get('client-scopes').value, /offline_access/);
  assert.equal(get('client-audience').value, 'https://resource.example/api/one,two');
  get('client-id').value = 'new-client'; get('client-name').value = 'New client'; get('client-redirects').value = 'https://app.example/cb';
  await submit();
  assert.deepEqual(JSON.parse(calls.filter(c => c.opts.method === 'POST').at(-1).opts.body).audience, ['https://resource.example/api/one,two']);
  current = {...fixture(true)}; handler = normalAPI;
  await ctx.clients('c1', 'edit');
  await submit();
  assert.deepEqual(JSON.parse(calls.filter(c => c.opts.method === 'PUT').at(-1).opts.body).audience, ['https://resource.example/api/one,two']);
  get('client-audience').value = '';
  await submit();
  assert.deepEqual(JSON.parse(calls.filter(c => c.opts.method === 'PUT').at(-1).opts.body).audience, []);
  current = {...fixture(true)}; delete current.audience; handler = normalAPI;
  await ctx.clients('c1', 'edit');
  await submit();
  assert.deepEqual(JSON.parse(calls.filter(c => c.opts.method === 'PUT').at(-1).opts.body).audience, []);
  current = fixture(true); handler = normalAPI;
  await ctx.clients('c1', 'edit');
  handler = async (_url, opts) => opts.method === 'POST' ? {secret: 'first'} : {secret: 'second', _headers: {get: () => '"29"'}};
  await get('client-secret-read').onclick();
  assert.equal(get('client-secret').textContent, 'first');
  await get('client-secret-rotate').onclick();
  assert.equal(get('client-secret').textContent, 'second');
  let release;
  handler = async () => new Promise(resolve => { release = resolve; });
  const count = calls.length, pending = submit();
  assert.equal(get('client-secret').textContent, 'Secret is hidden.');
  assert.ok(buttons().every(b => b.disabled));
  await submit();
  assert.equal(calls.length, count + 1);
  assert.equal(calls.at(-1).opts.headers['If-Match'], '"29"');
  handler = normalAPI; release({...current}); await pending;
  assert.ok(buttons().every(b => !b.disabled));
  handler = async () => { throw Error('409 conflict'); };
  get('client-name').value = 'Keep my input';
  await submit();
  assert.equal(get('client-name').value, 'Keep my input');
  assert.match(get('client-result').textContent, /Conflict/);
  handler = async () => ({secret: 'unversioned'});
  await get('client-secret-rotate').onclick();
  assert.match(get('client-result').textContent, /[Rr]eload/);
  assert.equal(get('client-secret').textContent, 'Secret is hidden.');
  console.log('clients UI form, policy, revision and pending regressions passed');
})().catch(err => { console.error(err); process.exitCode = 1; });
