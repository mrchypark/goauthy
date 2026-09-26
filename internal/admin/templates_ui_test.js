const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const nodes = new Map();
const node = id => nodes.get(id) || (nodes.set(id, {id, innerHTML: '', textContent: '', value: '', appendChild() {}}), nodes.get(id));
const ctx = {
  console,
  document: {getElementById: node, createElement: () => ({value: '', textContent: ''})},
  esc: value => String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c])),
  shell: (_title, _subtitle, html) => { for (const match of html.matchAll(/id="([^"]+)"/g)) node(match[1]); },
  api: async () => ({types: ['password_reset', 'registered_already'], languages: {password_reset: ['en', 'ko'], registered_already: ['en']}}),
};
vm.runInNewContext(fs.readFileSync(__dirname + '/templates.js', 'utf8'), ctx);

(async () => {
  await ctx.templates();
  const type = node('template-type'), language = node('template-lang'), preview = node('template-preview');
  type.value = 'password_reset'; type.onchange();
  language.value = 'ko'; language.onchange();
  assert.match(preview.innerHTML, /type=password_reset&lang=ko/);
  assert.doesNotMatch(preview.innerHTML, /\sstyle=/);
  type.value = 'registered_already'; type.onchange();
  assert.equal(preview.innerHTML, '');
  assert.match(language.innerHTML, /Select language/);
  console.log('email template UI checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
