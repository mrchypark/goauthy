const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(__dirname + '/catalog.js', 'utf8');
const elements = new Map(), calls = [], app = {innerHTML: ''};
const document = {getElementById(id) { if (!elements.has(id)) elements.set(id, {innerHTML: '', value: '', checked: false, textContent: '', className: ''}); return elements.get(id); }};
const ctx = {document, console, confirm: () => true, encodeURIComponent, root: app,
  esc: v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),
  split: v => v.split(',').map(x => x.trim()).filter(Boolean), shell: (_, __, body) => { app.innerHTML = body; for (const id of ['catalog-status', 'catalog-list', 'catalog-form', 'catalog-desc', 'catalog-default', 'catalog-type', 'catalog-editable', 'catalog-result', 'catalog-delete']) document.getElementById(id); },
  api: async (url, opts = {}) => { calls.push({url, opts}); if (ctx.failNext) { ctx.failNext = false; throw Error('backend unavailable'); } return opts.method ? {} : (url.includes('/attr') ? {values: [{name: 'staff', desc: '<x>', default_value: false, typ: 'email', user_editable: true}]} : [{scope: 'staff', attr_include_access: ['staff'], attr_include_id: []}]); }};
vm.runInNewContext(source, ctx);
(async () => {
  await ctx.catalog('attributes');
  assert.match(document.getElementById('catalog-list').innerHTML, /staff/);
  await ctx.catalog('attributes', 'staff');
  document.getElementById('catalog-desc').value = 'changed';
  document.getElementById('catalog-default').value = 'false';
  await document.getElementById('catalog-form').onsubmit({preventDefault() {}});
  assert.equal(calls.at(-2).url, '/auth/v1/users/attr/staff');
  assert.equal(calls.at(-2).opts.method, 'PUT');
  assert.equal(JSON.parse(calls.at(-2).opts.body).default_value, false);
  await ctx.catalog('attributes', 'staff');
  document.getElementById('catalog-default').value = '';
  await document.getElementById('catalog-form').onsubmit({preventDefault() {}});
  assert.equal('default_value' in JSON.parse(calls.at(-2).opts.body), false);
  await ctx.catalog('attributes', 'new');
  assert.match(app.innerHTML, /Cancel/);
  document.getElementById('catalog-name').value = 'new-attr';
  document.getElementById('catalog-default').value = '{"enabled":true}';
  await document.getElementById('catalog-form').onsubmit({preventDefault() {}});
  assert.equal(calls.at(-2).url, '/auth/v1/users/attr');
  assert.equal(calls.at(-2).opts.method, 'POST');
  assert.deepEqual(JSON.parse(calls.at(-2).opts.body).default_value, {enabled: true});
  await ctx.catalog('scopes', 'new');
  document.getElementById('catalog-name').value = 'new-scope';
  document.getElementById('catalog-access').value = 'staff';
  await document.getElementById('catalog-form').onsubmit({preventDefault() {}});
  assert.equal(calls.at(-2).url, '/auth/v1/scopes');
  assert.equal(calls.at(-2).opts.method, 'POST');
  assert.deepEqual(JSON.parse(calls.at(-2).opts.body).attr_include_access, ['staff']);
  ctx.failNext = true;
  await ctx.catalog('attributes');
  assert.match(document.getElementById('catalog-list').innerHTML, /backend unavailable/);
  await ctx.catalog('scopes', 'staff');
  await document.getElementById('catalog-delete').onclick();
  assert.equal(calls.at(-2).url, '/auth/v1/scopes/staff');
  assert.equal(calls.at(-2).opts.method, 'DELETE');
  console.log('catalog UI behavioral checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
