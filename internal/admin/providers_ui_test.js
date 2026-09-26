const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const nodes = new Map(), calls = [];
const node = id => nodes.get(id) || null;
const controls = () => [...nodes.values()].filter(item => ['INPUT', 'SELECT', 'TEXTAREA', 'BUTTON'].includes(item.tagName));
const decode = value => value.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
let release;
const ctx = {
  console, encodeURIComponent,
  location: {href: ''},
  confirm: () => true,
  esc: value => String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c])),
  document: {
    getElementById: node,
    querySelectorAll: selector => selector.startsWith('#provider-form ') ? controls() : [],
  },
  shell: (_title, _subtitle, html) => {
    nodes.clear();
    for (const match of html.matchAll(/<(\w+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
      const tagName = match[1].toUpperCase(), attrs = match[2];
      let value = /\bvalue="([^"]*)"/.exec(attrs)?.[1] || '';
      if (tagName === 'TEXTAREA') value = html.slice(match.index + match[0].length).split('</textarea>')[0];
      nodes.set(match[3], {id: match[3], tagName, value: decode(value), checked: /\schecked(?:\s|$)/.test(attrs), hidden: /\shidden(?:\s|$)/.test(attrs), disabled: false, innerHTML: '', textContent: '', className: ''});
    }
  },
  api: async (url, options = {}) => { calls.push({url, options}); return new Promise(resolve => { release = resolve; }); },
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(__dirname + '/providers.js', 'utf8'), ctx);

(async () => {
  const connector = {id: 'key-one', header: 'X-API-Key', prefix: '', operations: [{id: 'whoami', url: 'https://api.example.test/me', response_fields: {id: 'string'}}]};
  ctx.providerForm('', {}, false);
  node('prov-id').value = 'key-one'; node('prov-name').value = 'Key provider'; node('prov-kind').value = 'api_key'; node('prov-kind').onchange();
  assert.equal(node('prov-oauth-fields').hidden, true);
  assert.equal(node('prov-api-key-fields').hidden, false);
  node('prov-connector').value = JSON.stringify(connector);
  const submit = node('provider-form').onsubmit({preventDefault() {}});
  await Promise.resolve();
  const create = calls.at(-1);
  assert.equal(create.url, '/auth/v1/saas/providers');
  assert.equal(create.options.method, 'POST');
  assert.deepEqual(JSON.parse(create.options.body).connector, connector);
  assert.ok(controls().every(control => control.disabled));
  release({}); await submit;
  assert.ok(controls().every(control => !control.disabled));

  ctx.providerForm('', {}, false);
  node('prov-id').value = 'key-two'; node('prov-name').value = 'Broken'; node('prov-kind').value = 'api_key'; node('prov-kind').onchange(); node('prov-connector').value = '{';
  const before = calls.length;
  await node('provider-form').onsubmit({preventDefault() {}});
  assert.equal(calls.length, before);
  assert.match(node('prov-result').textContent, /valid JSON/);
  console.log('provider UI API-key and pending checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
