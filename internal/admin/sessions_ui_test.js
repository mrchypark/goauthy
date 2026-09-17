const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(__dirname + '/sessions.js', 'utf8');
const nodes = new Map(), calls = [];
const node = id => nodes.get(id) || (nodes.set(id, {id, innerHTML: '', value: '', checked: false, textContent: '', dataset: {}, className: ''}), nodes.get(id));
const document = {getElementById: node};
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api = async (path, opts = {}) => { calls.push({path, opts}); return ctx.reply; };
const ctx = {document, console, URLSearchParams, encodeURIComponent, confirm: () => true,
  location: {pathname: '/auth/v1/admin/sessions', search: ''}, history: {replaceState(_, __, url) { ctx.location.search = url.split('?')[1] ? '?' + url.split('?')[1] : ''; }},
  root: {innerHTML: ''}, shell: (_, __, body) => { node('app').innerHTML = body; for (const id of body.matchAll(/(?:id|data-[a-z-]+)="([^"]+)"/g)) node(id[1]); }, esc, api};
ctx.reply = Object.assign([{id: 'sid/1', user_id: '<subject>', state: 'Auth', last_seen: 1, exp: 2, remote_ip: '1.2.3.4'}], {_headers: {get: n => ({'X-Page-Count': '2', 'X-Continuation-Token': 'cursor/next'}[n] || null)}});
vm.runInNewContext(source, ctx);
(async () => {
  await ctx.sessions();
  assert.equal(calls[0].path, '/auth/v1/sessions?session_state=Auth&page_size=20');
  assert.match(node('session-table').innerHTML, /&lt;subject&gt;/);
  assert.match(node('session-table').innerHTML, /data-revoke-session="sid\/1"/);
  assert.match(node('session-paging').innerHTML, /Next page/);

  node('session-state').value = 'Unknown'; node('session-page-size').value = '7';
  await node('session-filter').onsubmit({preventDefault() {}});
  assert.match(calls.at(-1).path, /session_state=Unknown&page_size=7/);

  const beforeCancel = calls.length; ctx.confirm = () => false;
  await node('session-table').onclick({target: {dataset: {revokeSession: 'sid/1'}}});
  assert.equal(calls.length, beforeCancel);
  ctx.confirm = () => true; ctx.reply = [];
  await node('session-table').onclick({target: {dataset: {forceSubject: 'member/1'}}});
  assert.equal(calls.at(-2).path, '/auth/v1/sessions/member%2F1');
  assert.equal(calls.at(-2).opts.method, 'DELETE');
  ctx.api = async () => { throw Error('backend unavailable'); };
  await ctx.sessions(); assert.match(node('session-table').textContent, /backend unavailable/);
  ctx.api = api;

  node('global-ack').checked = false; await node('global-logout').onsubmit({preventDefault() {}});
  assert.match(node('global-result').textContent, /current administrator session/);
  const beforeGlobal = calls.length; node('global-ack').checked = true; ctx.confirm = () => false;
  await node('global-logout').onsubmit({preventDefault() {}}); assert.equal(calls.length, beforeGlobal);
  ctx.confirm = () => true; ctx.reply = undefined;
  await node('global-logout').onsubmit({preventDefault() {}});
  assert.equal(calls.at(-1).path, '/auth/v1/sessions'); assert.equal(calls.at(-1).opts.method, 'DELETE');
  assert.match(ctx.root.innerHTML, /Global logout complete/);
  console.log('sessions UI behavioral checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
